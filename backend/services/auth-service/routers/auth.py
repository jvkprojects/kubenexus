"""
Authentication router for KubeNexus Authentication Service.
Handles login, logout, token refresh, and SSO authentication.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr, Field
import httpx
import ldap
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    get_settings,
    PasswordManager,
    TokenManager,
    SessionManager,
    LoginAttemptTracker,
    AuthenticationError,
    User,
    audit_logger,
    security_logger,
    get_current_user
)

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()


# Pydantic models for request/response
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1)
    remember_me: bool = False


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class TokenRefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class SSOCallbackRequest(BaseModel):
    code: str
    state: Optional[str] = None


def get_client_info(request: Request) -> Dict[str, str]:
    """Extract client information from request."""
    return {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "")
    }


@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Authenticate user with username/password."""
    
    client_info = get_client_info(request)
    
    # Check if account is locked
    if await LoginAttemptTracker.is_account_locked(login_data.username):
        security_logger.log_authentication_attempt(
            username=login_data.username,
            success=False,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            failure_reason="account_locked"
        )
        raise AuthenticationError("Account is temporarily locked due to too many failed attempts")
    
    try:
        # Get user from database
        result = await db.execute(
            select(User).where(User.username == login_data.username)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            await LoginAttemptTracker.record_failed_attempt(login_data.username)
            security_logger.log_authentication_attempt(
                username=login_data.username,
                success=False,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
                failure_reason="user_not_found"
            )
            raise AuthenticationError("Invalid username or password")
        
        # Check user status
        if user.status != "active":
            security_logger.log_authentication_attempt(
                username=login_data.username,
                success=False,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
                failure_reason="account_inactive"
            )
            raise AuthenticationError("Account is inactive")
        
        # Verify password
        if not user.password_hash or not PasswordManager.verify_password(
            login_data.password, user.password_hash
        ):
            await LoginAttemptTracker.record_failed_attempt(login_data.username)
            security_logger.log_authentication_attempt(
                username=login_data.username,
                success=False,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
                failure_reason="invalid_password"
            )
            raise AuthenticationError("Invalid username or password")
        
        # Clear failed attempts on successful login
        await LoginAttemptTracker.clear_failed_attempts(login_data.username)
        
        # Generate tokens
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email
        }
        
        # Set token expiration based on remember_me
        if login_data.remember_me:
            access_token_expires = timedelta(days=7)
        else:
            access_token_expires = timedelta(minutes=settings.jwt_expire_minutes)
        
        access_token = TokenManager.create_access_token(
            data=token_data,
            expires_delta=access_token_expires
        )
        refresh_token = TokenManager.create_refresh_token(data=token_data)
        
        # Create session
        session_id = await SessionManager.create_session(
            user_id=str(user.id),
            access_token=access_token,
            refresh_token=refresh_token,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        
        # Update last login time
        user.last_login_at = datetime.now(timezone.utc)
        await db.commit()
        
        # Log successful authentication
        security_logger.log_authentication_attempt(
            username=login_data.username,
            success=True,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            auth_method="local"
        )
        
        audit_logger.log_user_action(
            user_id=str(user.id),
            action="login",
            resource_type="auth",
            resource_name="user_session",
            success=True,
            additional_data={
                "ip_address": client_info["ip_address"],
                "session_id": session_id
            }
        )
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(access_token_expires.total_seconds()),
            user={
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "status": user.status,
                "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None
            }
        )
        
    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"Login failed for {login_data.username}: {e}", exc_info=True)
        raise AuthenticationError("Authentication failed")


@router.post("/logout")
async def logout(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Logout user and invalidate tokens."""
    
    try:
        # Get token from header
        authorization = request.headers.get("authorization", "")
        if authorization.startswith("Bearer "):
            token = authorization.replace("Bearer ", "")
            
            # Blacklist the token
            await TokenManager.blacklist_token(token)
            
            # Invalidate all user sessions
            await SessionManager.invalidate_all_user_sessions(current_user["id"])
            
            # Log logout
            audit_logger.log_user_action(
                user_id=current_user["id"],
                action="logout",
                resource_type="auth",
                resource_name="user_session",
                success=True
            )
            
            logger.info(f"User {current_user['username']} logged out successfully")
            
            return {"message": "Successfully logged out"}
        
        raise AuthenticationError("No valid token found")
        
    except Exception as e:
        logger.error(f"Logout failed for user {current_user.get('id')}: {e}", exc_info=True)
        raise AuthenticationError("Logout failed")


@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(
    refresh_data: TokenRefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Refresh access token using refresh token."""
    
    try:
        # Verify refresh token
        payload = TokenManager.verify_token(refresh_data.refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise AuthenticationError("Invalid refresh token")
        
        # Check if token is blacklisted
        if await TokenManager.is_token_blacklisted(refresh_data.refresh_token):
            raise AuthenticationError("Refresh token has been revoked")
        
        # Get user from database
        user_id = payload.get("sub")
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user or user.status != "active":
            raise AuthenticationError("User not found or inactive")
        
        # Generate new access token
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email
        }
        
        access_token = TokenManager.create_access_token(data=token_data)
        expires_in = settings.jwt_expire_minutes * 60
        
        logger.info(f"Token refreshed for user {user.username}")
        
        return TokenRefreshResponse(
            access_token=access_token,
            expires_in=expires_in
        )
        
    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}", exc_info=True)
        raise AuthenticationError("Token refresh failed")


@router.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Change user password."""
    
    try:
        # Get user from database
        result = await db.execute(
            select(User).where(User.id == current_user["id"])
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise AuthenticationError("User not found")
        
        # Verify current password
        if not user.password_hash or not PasswordManager.verify_password(
            password_data.current_password, user.password_hash
        ):
            audit_logger.log_user_action(
                user_id=current_user["id"],
                action="change_password",
                resource_type="auth",
                resource_name="user_password",
                success=False,
                error_message="Invalid current password"
            )
            raise AuthenticationError("Invalid current password")
        
        # Validate new password strength
        is_valid, errors = PasswordManager.validate_password_strength(password_data.new_password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Password does not meet requirements", "errors": errors}
            )
        
        # Update password
        user.password_hash = PasswordManager.hash_password(password_data.new_password)
        await db.commit()
        
        # Invalidate all user sessions (force re-login)
        await SessionManager.invalidate_all_user_sessions(current_user["id"])
        
        # Log password change
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="change_password",
            resource_type="auth",
            resource_name="user_password",
            success=True
        )
        
        logger.info(f"Password changed for user {user.username}")
        
        return {"message": "Password changed successfully. Please log in again."}
        
    except AuthenticationError:
        raise
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change failed for user {current_user.get('id')}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )


@router.post("/ldap-login", response_model=LoginResponse)
async def ldap_login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Authenticate user with LDAP."""
    
    if not settings.ldap_server:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="LDAP authentication is not configured"
        )
    
    client_info = get_client_info(request)
    
    try:
        # Connect to LDAP server
        ldap_conn = ldap.initialize(f"ldap://{settings.ldap_server}:{settings.ldap_port}")
        if settings.ldap_use_ssl:
            ldap_conn.start_tls_s()
        
        # Bind with service account
        if settings.ldap_user_dn and settings.ldap_password:
            ldap_conn.simple_bind_s(settings.ldap_user_dn, settings.ldap_password)
        
        # Search for user
        search_filter = settings.ldap_user_search.format(username=login_data.username)
        search_attrs = ['uid', 'cn', 'mail', 'dn']
        
        result = ldap_conn.search_s(
            settings.ldap_base_dn,
            ldap.SCOPE_SUBTREE,
            search_filter,
            search_attrs
        )
        
        if not result:
            security_logger.log_authentication_attempt(
                username=login_data.username,
                success=False,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
                auth_method="ldap",
                failure_reason="user_not_found"
            )
            raise AuthenticationError("Invalid username or password")
        
        # Get user DN and attributes
        user_dn, user_attrs = result[0]
        
        # Authenticate user
        try:
            ldap_conn.simple_bind_s(user_dn, login_data.password)
        except ldap.INVALID_CREDENTIALS:
            security_logger.log_authentication_attempt(
                username=login_data.username,
                success=False,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"],
                auth_method="ldap",
                failure_reason="invalid_password"
            )
            raise AuthenticationError("Invalid username or password")
        
        # Get or create user in database
        result = await db.execute(
            select(User).where(User.username == login_data.username)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            # Create new user from LDAP attributes
            user = User(
                username=login_data.username,
                email=user_attrs.get('mail', [b''])[0].decode('utf-8') if user_attrs.get('mail') else f"{login_data.username}@ldap.local",
                ldap_dn=user_dn,
                first_name=user_attrs.get('cn', [b''])[0].decode('utf-8') if user_attrs.get('cn') else login_data.username,
                status='active'
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
        else:
            # Update LDAP DN if changed
            user.ldap_dn = user_dn
            user.last_login_at = datetime.now(timezone.utc)
            await db.commit()
        
        # Generate tokens and create session (same as local login)
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email
        }
        
        access_token_expires = timedelta(minutes=settings.jwt_expire_minutes)
        access_token = TokenManager.create_access_token(data=token_data, expires_delta=access_token_expires)
        refresh_token = TokenManager.create_refresh_token(data=token_data)
        
        session_id = await SessionManager.create_session(
            user_id=str(user.id),
            access_token=access_token,
            refresh_token=refresh_token,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        
        security_logger.log_authentication_attempt(
            username=login_data.username,
            success=True,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            auth_method="ldap"
        )
        
        audit_logger.log_user_action(
            user_id=str(user.id),
            action="login",
            resource_type="auth",
            resource_name="user_session",
            success=True,
            additional_data={
                "auth_method": "ldap",
                "ip_address": client_info["ip_address"],
                "session_id": session_id
            }
        )
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=int(access_token_expires.total_seconds()),
            user={
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "status": user.status,
                "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None
            }
        )
        
    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"LDAP login failed for {login_data.username}: {e}", exc_info=True)
        raise AuthenticationError("LDAP authentication failed")
    finally:
        try:
            ldap_conn.unbind_s()
        except:
            pass


@router.get("/sso/redirect")
async def sso_redirect():
    """Redirect to SSO provider."""
    
    if not settings.sso_client_id or not settings.sso_discovery_url:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="SSO is not configured"
        )
    
    # Generate state parameter for CSRF protection
    import secrets
    state = secrets.token_urlsafe(32)
    
    # Build authorization URL
    auth_url = f"{settings.sso_discovery_url}/auth"
    params = {
        "client_id": settings.sso_client_id,
        "response_type": "code",
        "scope": " ".join(settings.sso_scopes),
        "redirect_uri": settings.sso_redirect_uri,
        "state": state
    }
    
    query_string = "&".join([f"{k}={v}" for k, v in params.items()])
    redirect_url = f"{auth_url}?{query_string}"
    
    return {"redirect_url": redirect_url, "state": state}


@router.post("/sso/callback", response_model=LoginResponse)
async def sso_callback(
    callback_data: SSOCallbackRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Handle SSO callback and authenticate user."""
    
    if not settings.sso_client_id or not settings.sso_client_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="SSO is not configured"
        )
    
    client_info = get_client_info(request)
    
    try:
        # Exchange code for tokens
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                f"{settings.sso_discovery_url}/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": settings.sso_client_id,
                    "client_secret": settings.sso_client_secret,
                    "code": callback_data.code,
                    "redirect_uri": settings.sso_redirect_uri
                }
            )
        
        if token_response.status_code != 200:
            raise AuthenticationError("Failed to exchange authorization code")
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        
        # Get user info from SSO provider
        async with httpx.AsyncClient() as client:
            user_response = await client.get(
                f"{settings.sso_discovery_url}/userinfo",
                headers={"Authorization": f"Bearer {access_token}"}
            )
        
        if user_response.status_code != 200:
            raise AuthenticationError("Failed to get user information")
        
        user_info = user_response.json()
        
        # Get or create user in database
        sso_id = user_info.get("sub")
        email = user_info.get("email")
        username = user_info.get("preferred_username") or email
        
        result = await db.execute(
            select(User).where(User.sso_id == sso_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            # Create new user from SSO
            user = User(
                username=username,
                email=email,
                sso_id=sso_id,
                first_name=user_info.get("given_name", ""),
                last_name=user_info.get("family_name", ""),
                status='active'
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
        else:
            # Update user info
            user.last_login_at = datetime.now(timezone.utc)
            await db.commit()
        
        # Generate our own tokens
        token_data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email
        }
        
        access_token_expires = timedelta(minutes=settings.jwt_expire_minutes)
        our_access_token = TokenManager.create_access_token(data=token_data, expires_delta=access_token_expires)
        our_refresh_token = TokenManager.create_refresh_token(data=token_data)
        
        session_id = await SessionManager.create_session(
            user_id=str(user.id),
            access_token=our_access_token,
            refresh_token=our_refresh_token,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        
        security_logger.log_authentication_attempt(
            username=user.username,
            success=True,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            auth_method="sso"
        )
        
        audit_logger.log_user_action(
            user_id=str(user.id),
            action="login",
            resource_type="auth",
            resource_name="user_session",
            success=True,
            additional_data={
                "auth_method": "sso",
                "ip_address": client_info["ip_address"],
                "session_id": session_id
            }
        )
        
        return LoginResponse(
            access_token=our_access_token,
            refresh_token=our_refresh_token,
            expires_in=int(access_token_expires.total_seconds()),
            user={
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "status": user.status,
                "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None
            }
        )
        
    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"SSO callback failed: {e}", exc_info=True)
        raise AuthenticationError("SSO authentication failed")


# Import current_user dependency at the end to avoid circular imports
from shared import get_current_user 