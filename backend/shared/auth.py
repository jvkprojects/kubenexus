"""
Shared authentication utilities for KubeNexus backend services.
Provides JWT token management, password hashing, and authentication helpers.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union
import re
from functools import wraps

from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import redis
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .database import get_async_db_dependency

logger = logging.getLogger(__name__)
settings = get_settings()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer scheme for token extraction
security = HTTPBearer()

# Redis client for token blacklisting and session management
redis_client = None


def init_redis():
    """Initialize Redis client for authentication."""
    global redis_client
    try:
        redis_client = redis.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=settings.redis_max_connections,
            socket_timeout=settings.redis_socket_timeout,
            socket_connect_timeout=settings.redis_socket_connect_timeout,
            health_check_interval=settings.redis_health_check_interval
        )
        logger.info("Redis client initialized for authentication")
    except Exception as e:
        logger.error(f"Failed to initialize Redis client: {e}")
        raise


class PasswordManager:
    """Password management utilities."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, list[str]]:
        """
        Validate password strength based on security requirements.
        Returns (is_valid, list_of_errors)
        """
        errors = []
        
        if len(password) < settings.password_min_length:
            errors.append(f"Password must be at least {settings.password_min_length} characters long")
        
        if settings.password_require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if settings.password_require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if settings.password_require_numbers and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if settings.password_require_special and not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors


class TokenManager:
    """JWT token management utilities."""
    
    @staticmethod
    def create_access_token(
        data: Dict[str, Any], 
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access"
        })
        
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.jwt_secret, 
            algorithm=settings.jwt_algorithm
        )
        return encoded_jwt
    
    @staticmethod
    def create_refresh_token(data: Dict[str, Any]) -> str:
        """Create JWT refresh token."""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_expire_days)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "refresh"
        })
        
        encoded_jwt = jwt.encode(
            to_encode,
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm
        )
        return encoded_jwt
    
    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm]
            )
            return payload
        except JWTError as e:
            logger.warning(f"JWT verification failed: {e}")
            return None
    
    @staticmethod
    def extract_user_id(token: str) -> Optional[str]:
        """Extract user ID from JWT token."""
        payload = TokenManager.verify_token(token)
        if payload:
            return payload.get("sub")
        return None
    
    @staticmethod
    def is_token_expired(token: str) -> bool:
        """Check if token is expired."""
        payload = TokenManager.verify_token(token)
        if not payload:
            return True
        
        exp = payload.get("exp")
        if not exp:
            return True
        
        return datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc)
    
    @staticmethod
    async def blacklist_token(token: str, expires_in: Optional[int] = None):
        """Add token to blacklist in Redis."""
        if not redis_client:
            logger.warning("Redis client not initialized, cannot blacklist token")
            return
        
        try:
            key = f"blacklist:token:{token}"
            if expires_in is None:
                # Set expiration based on token's remaining lifetime
                payload = TokenManager.verify_token(token)
                if payload and payload.get("exp"):
                    exp_timestamp = payload["exp"]
                    current_timestamp = datetime.now(timezone.utc).timestamp()
                    expires_in = max(0, int(exp_timestamp - current_timestamp))
                else:
                    expires_in = settings.jwt_expire_minutes * 60
            
            await redis_client.setex(key, expires_in, "blacklisted")
            logger.info(f"Token blacklisted successfully")
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e}")
    
    @staticmethod
    async def is_token_blacklisted(token: str) -> bool:
        """Check if token is blacklisted."""
        if not redis_client:
            return False
        
        try:
            key = f"blacklist:token:{token}"
            exists = await redis_client.exists(key)
            return bool(exists)
        except Exception as e:
            logger.error(f"Failed to check token blacklist status: {e}")
            return False


class SessionManager:
    """User session management utilities."""
    
    @staticmethod
    async def create_session(
        user_id: str,
        access_token: str,
        refresh_token: str,
        ip_address: str,
        user_agent: str
    ) -> str:
        """Create user session in Redis."""
        if not redis_client:
            raise RuntimeError("Redis client not initialized")
        
        session_id = f"session:{user_id}:{datetime.now(timezone.utc).timestamp()}"
        session_data = {
            "user_id": user_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_accessed_at": datetime.now(timezone.utc).isoformat()
        }
        
        try:
            await redis_client.hset(session_id, mapping=session_data)
            await redis_client.expire(session_id, settings.session_timeout)
            return session_id
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise
    
    @staticmethod
    async def get_session(session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data from Redis."""
        if not redis_client:
            return None
        
        try:
            session_data = await redis_client.hgetall(session_id)
            if session_data:
                # Update last accessed time
                await redis_client.hset(
                    session_id, 
                    "last_accessed_at", 
                    datetime.now(timezone.utc).isoformat()
                )
                await redis_client.expire(session_id, settings.session_timeout)
            return session_data
        except Exception as e:
            logger.error(f"Failed to get session: {e}")
            return None
    
    @staticmethod
    async def invalidate_session(session_id: str):
        """Invalidate user session."""
        if not redis_client:
            return
        
        try:
            await redis_client.delete(session_id)
            logger.info(f"Session {session_id} invalidated")
        except Exception as e:
            logger.error(f"Failed to invalidate session: {e}")
    
    @staticmethod
    async def invalidate_all_user_sessions(user_id: str):
        """Invalidate all sessions for a user."""
        if not redis_client:
            return
        
        try:
            pattern = f"session:{user_id}:*"
            sessions = await redis_client.keys(pattern)
            if sessions:
                await redis_client.delete(*sessions)
                logger.info(f"Invalidated {len(sessions)} sessions for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to invalidate user sessions: {e}")


class AuthenticationError(HTTPException):
    """Custom authentication error."""
    
    def __init__(self, detail: str = "Could not validate credentials"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class AuthorizationError(HTTPException):
    """Custom authorization error."""
    
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_async_db_dependency)
) -> Dict[str, Any]:
    """
    Dependency to get current authenticated user.
    Validates JWT token and returns user information.
    """
    token = credentials.credentials
    
    # Check if token is blacklisted
    if await TokenManager.is_token_blacklisted(token):
        raise AuthenticationError("Token has been revoked")
    
    # Verify token
    payload = TokenManager.verify_token(token)
    if not payload:
        raise AuthenticationError("Invalid token")
    
    # Check token type
    if payload.get("type") != "access":
        raise AuthenticationError("Invalid token type")
    
    # Extract user information
    user_id = payload.get("sub")
    if not user_id:
        raise AuthenticationError("Token missing user information")
    
    # Get user from database
    from .models import User  # Import here to avoid circular imports
    
    try:
        result = await db.execute(
            "SELECT id, username, email, status FROM users WHERE id = :user_id",
            {"user_id": user_id}
        )
        user_row = result.fetchone()
        
        if not user_row:
            raise AuthenticationError("User not found")
        
        if user_row.status != "active":
            raise AuthenticationError("User account is inactive")
        
        return {
            "id": str(user_row.id),
            "username": user_row.username,
            "email": user_row.email,
            "status": user_row.status,
            "token_payload": payload
        }
        
    except Exception as e:
        logger.error(f"Failed to get current user: {e}")
        raise AuthenticationError("Authentication failed")


async def get_current_active_user(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Dependency to get current active user.
    """
    if current_user["status"] != "active":
        raise AuthenticationError("User account is inactive")
    return current_user


def require_permissions(*required_permissions: str):
    """
    Decorator to require specific permissions for accessing endpoints.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from kwargs or call dependency
            current_user = kwargs.get("current_user")
            if not current_user:
                # If not in kwargs, this decorator must be used with get_current_user dependency
                raise RuntimeError("require_permissions decorator requires current_user dependency")
            
            # Check user permissions
            user_id = current_user["id"]
            
            # Get user permissions from database
            db = kwargs.get("db")
            if not db:
                raise RuntimeError("require_permissions decorator requires database session")
            
            # Query user permissions
            result = await db.execute("""
                SELECT DISTINCT p.name 
                FROM permissions p
                JOIN role_permissions rp ON p.id = rp.permission_id
                JOIN user_roles ur ON rp.role_id = ur.role_id
                WHERE ur.user_id = :user_id
                AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
            """, {"user_id": user_id})
            
            user_permissions = {row.name for row in result.fetchall()}
            
            # Check if user has required permissions
            missing_permissions = set(required_permissions) - user_permissions
            if missing_permissions:
                raise AuthorizationError(
                    f"Missing required permissions: {', '.join(missing_permissions)}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_permission(permission: str):
    """
    Decorator to require a single permission for accessing endpoints.
    Wrapper around require_permissions for convenience.
    """
    return require_permissions(permission)


def require_role(*required_roles: str):
    """
    Decorator to require specific roles for accessing endpoints.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get("current_user")
            if not current_user:
                raise RuntimeError("require_role decorator requires current_user dependency")
            
            user_id = current_user["id"]
            db = kwargs.get("db")
            if not db:
                raise RuntimeError("require_role decorator requires database session")
            
            # Query user roles
            result = await db.execute("""
                SELECT DISTINCT r.name 
                FROM roles r
                JOIN user_roles ur ON r.id = ur.role_id
                WHERE ur.user_id = :user_id
                AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
            """, {"user_id": user_id})
            
            user_roles = {row.name for row in result.fetchall()}
            
            # Check if user has required roles
            has_required_role = any(role in user_roles for role in required_roles)
            if not has_required_role:
                raise AuthorizationError(
                    f"Missing required role. Required one of: {', '.join(required_roles)}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Rate limiting utilities
class RateLimiter:
    """Rate limiting utilities."""
    
    @staticmethod
    async def is_rate_limited(
        key: str, 
        limit: int = None, 
        window: int = 60
    ) -> bool:
        """Check if a key is rate limited."""
        if not redis_client:
            return False
        
        if limit is None:
            limit = settings.rate_limit_per_minute
        
        try:
            current_count = await redis_client.incr(f"rate_limit:{key}")
            if current_count == 1:
                await redis_client.expire(f"rate_limit:{key}", window)
            
            return current_count > limit
        except Exception as e:
            logger.error(f"Rate limiting check failed: {e}")
            return False
    
    @staticmethod
    async def get_rate_limit_info(key: str) -> Dict[str, Any]:
        """Get rate limit information for a key."""
        if not redis_client:
            return {"count": 0, "ttl": 0}
        
        try:
            count = await redis_client.get(f"rate_limit:{key}") or 0
            ttl = await redis_client.ttl(f"rate_limit:{key}")
            return {"count": int(count), "ttl": ttl}
        except Exception as e:
            logger.error(f"Failed to get rate limit info: {e}")
            return {"count": 0, "ttl": 0}


# Login attempt tracking
class LoginAttemptTracker:
    """Track login attempts and implement account lockout."""
    
    @staticmethod
    async def record_failed_attempt(identifier: str):
        """Record a failed login attempt."""
        if not redis_client:
            return
        
        key = f"login_attempts:{identifier}"
        try:
            attempts = await redis_client.incr(key)
            if attempts == 1:
                await redis_client.expire(key, settings.lockout_duration)
            
            if attempts >= settings.max_login_attempts:
                # Lock the account
                lock_key = f"account_locked:{identifier}"
                await redis_client.setex(lock_key, settings.lockout_duration, "locked")
                logger.warning(f"Account locked due to too many failed attempts: {identifier}")
                
        except Exception as e:
            logger.error(f"Failed to record login attempt: {e}")
    
    @staticmethod
    async def clear_failed_attempts(identifier: str):
        """Clear failed login attempts for successful login."""
        if not redis_client:
            return
        
        try:
            await redis_client.delete(f"login_attempts:{identifier}")
        except Exception as e:
            logger.error(f"Failed to clear login attempts: {e}")
    
    @staticmethod
    async def is_account_locked(identifier: str) -> bool:
        """Check if account is locked."""
        if not redis_client:
            return False
        
        try:
            locked = await redis_client.exists(f"account_locked:{identifier}")
            return bool(locked)
        except Exception as e:
            logger.error(f"Failed to check account lock status: {e}")
            return False
    
    @staticmethod
    async def get_failed_attempts(identifier: str) -> int:
        """Get number of failed attempts."""
        if not redis_client:
            return 0
        
        try:
            attempts = await redis_client.get(f"login_attempts:{identifier}")
            return int(attempts) if attempts else 0
        except Exception as e:
            logger.error(f"Failed to get failed attempts count: {e}")
            return 0


# Initialize authentication components
def init_auth():
    """Initialize authentication components."""
    init_redis()
    logger.info("Authentication components initialized") 