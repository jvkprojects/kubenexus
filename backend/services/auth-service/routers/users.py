"""
Users router for KubeNexus Authentication Service.
Handles user management operations (CRUD).
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, EmailStr, Field, validator
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    get_settings,
    PasswordManager,
    User,
    Role,
    UserRole,
    Organization,
    audit_logger,
    require_permissions,
    get_current_user
)

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()


# Pydantic models for request/response
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: str = Field(..., max_length=255)
    last_name: str = Field(..., max_length=255)
    organization_id: Optional[str] = None
    role_ids: List[str] = []
    
    @validator('username')
    def validate_username(cls, v):
        if not v.replace('_', '').replace('-', '').isalnum():
            raise ValueError('Username can only contain letters, numbers, hyphens, and underscores')
        return v.lower()


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    first_name: Optional[str] = Field(None, max_length=255)
    last_name: Optional[str] = Field(None, max_length=255)
    organization_id: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(active|inactive|suspended)$")
    role_ids: Optional[List[str]] = None


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    first_name: str
    last_name: str
    full_name: str
    status: str
    organization_id: Optional[str]
    organization_name: Optional[str]
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime]
    sso_id: Optional[str]
    ldap_dn: Optional[str]
    roles: List[Dict[str, Any]]


class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int
    page: int
    size: int
    pages: int


class UserProfileUpdate(BaseModel):
    first_name: Optional[str] = Field(None, max_length=255)
    last_name: Optional[str] = Field(None, max_length=255)
    email: Optional[EmailStr] = None


@router.post("/", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("user:create"))
):
    """Create a new user."""
    
    try:
        # Check if username already exists
        result = await db.execute(
            select(User).where(User.username == user_data.username)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists"
            )
        
        # Check if email already exists
        result = await db.execute(
            select(User).where(User.email == user_data.email)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already exists"
            )
        
        # Validate password strength
        is_valid, errors = PasswordManager.validate_password_strength(user_data.password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"message": "Password does not meet requirements", "errors": errors}
            )
        
        # Validate organization if provided
        if user_data.organization_id:
            result = await db.execute(
                select(Organization).where(Organization.id == user_data.organization_id)
            )
            if not result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Organization not found"
                )
        
        # Validate roles
        if user_data.role_ids:
            result = await db.execute(
                select(Role).where(Role.id.in_(user_data.role_ids))
            )
            roles = result.scalars().all()
            if len(roles) != len(user_data.role_ids):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="One or more roles not found"
                )
        
        # Create user
        user = User(
            id=str(uuid4()),
            username=user_data.username,
            email=user_data.email,
            password_hash=PasswordManager.hash_password(user_data.password),
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            organization_id=user_data.organization_id,
            status='active'
        )
        
        db.add(user)
        await db.commit()
        await db.refresh(user)
        
        # Assign roles
        if user_data.role_ids:
            for role_id in user_data.role_ids:
                user_role = UserRole(
                    id=str(uuid4()),
                    user_id=user.id,
                    role_id=role_id
                )
                db.add(user_role)
            
            await db.commit()
        
        # Log user creation
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="create",
            resource_type="user",
            resource_id=user.id,
            resource_name=user.username,
            success=True,
            additional_data={
                "created_user_id": user.id,
                "organization_id": user_data.organization_id,
                "role_ids": user_data.role_ids
            }
        )
        
        logger.info(f"User {user.username} created by {current_user['username']}")
        
        # Get user with roles for response
        result = await db.execute(
            select(User)
            .options(joinedload(User.roles).joinedload(UserRole.role))
            .options(joinedload(User.organization))
            .where(User.id == user.id)
        )
        created_user = result.scalar_one()
        
        return _format_user_response(created_user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create user: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )


@router.get("/", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    organization_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("user:read"))
):
    """List users with filtering and pagination."""
    
    try:
        # Build query
        query = select(User).options(
            joinedload(User.roles).joinedload(UserRole.role),
            joinedload(User.organization)
        )
        
        conditions = []
        
        # Apply filters
        if search:
            search_term = f"%{search}%"
            conditions.append(
                or_(
                    User.username.ilike(search_term),
                    User.email.ilike(search_term),
                    User.first_name.ilike(search_term),
                    User.last_name.ilike(search_term)
                )
            )
        
        if organization_id:
            conditions.append(User.organization_id == organization_id)
        
        if status:
            conditions.append(User.status == status)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Get total count
        count_query = select(func.count(User.id))
        if conditions:
            count_query = count_query.where(and_(*conditions))
        
        result = await db.execute(count_query)
        total = result.scalar()
        
        # Apply pagination
        offset = (page - 1) * size
        query = query.offset(offset).limit(size)
        
        # Execute query
        result = await db.execute(query)
        users = result.scalars().unique().all()
        
        # Calculate pagination info
        pages = (total + size - 1) // size
        
        return UserListResponse(
            users=[_format_user_response(user) for user in users],
            total=total,
            page=page,
            size=size,
            pages=pages
        )
        
    except Exception as e:
        logger.error(f"Failed to list users: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list users"
        )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("user:read"))
):
    """Get user by ID."""
    
    try:
        result = await db.execute(
            select(User)
            .options(joinedload(User.roles).joinedload(UserRole.role))
            .options(joinedload(User.organization))
            .where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return _format_user_response(user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user {user_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user"
        )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("user:update"))
):
    """Update user."""
    
    try:
        # Get existing user
        result = await db.execute(
            select(User)
            .options(joinedload(User.roles).joinedload(UserRole.role))
            .options(joinedload(User.organization))
            .where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Check email uniqueness if changed
        if user_data.email and user_data.email != user.email:
            result = await db.execute(
                select(User).where(and_(User.email == user_data.email, User.id != user_id))
            )
            if result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already exists"
                )
        
        # Validate organization if provided
        if user_data.organization_id:
            result = await db.execute(
                select(Organization).where(Organization.id == user_data.organization_id)
            )
            if not result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Organization not found"
                )
        
        # Update user fields
        if user_data.email is not None:
            user.email = user_data.email
        if user_data.first_name is not None:
            user.first_name = user_data.first_name
        if user_data.last_name is not None:
            user.last_name = user_data.last_name
        if user_data.organization_id is not None:
            user.organization_id = user_data.organization_id
        if user_data.status is not None:
            user.status = user_data.status
        
        user.updated_at = datetime.now(timezone.utc)
        
        # Update roles if provided
        if user_data.role_ids is not None:
            # Validate roles
            if user_data.role_ids:
                result = await db.execute(
                    select(Role).where(Role.id.in_(user_data.role_ids))
                )
                roles = result.scalars().all()
                if len(roles) != len(user_data.role_ids):
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="One or more roles not found"
                    )
            
            # Remove existing roles
            await db.execute(
                select(UserRole).where(UserRole.user_id == user_id)
            )
            existing_roles = await db.execute(
                select(UserRole).where(UserRole.user_id == user_id)
            )
            for role in existing_roles.scalars():
                await db.delete(role)
            
            # Add new roles
            for role_id in user_data.role_ids:
                user_role = UserRole(
                    id=str(uuid4()),
                    user_id=user.id,
                    role_id=role_id
                )
                db.add(user_role)
        
        await db.commit()
        await db.refresh(user)
        
        # Log user update
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="update",
            resource_type="user",
            resource_id=user.id,
            resource_name=user.username,
            success=True,
            additional_data={
                "updated_fields": user_data.dict(exclude_unset=True)
            }
        )
        
        logger.info(f"User {user.username} updated by {current_user['username']}")
        
        # Get updated user with roles for response
        result = await db.execute(
            select(User)
            .options(joinedload(User.roles).joinedload(UserRole.role))
            .options(joinedload(User.organization))
            .where(User.id == user.id)
        )
        updated_user = result.scalar_one()
        
        return _format_user_response(updated_user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update user {user_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("user:delete"))
):
    """Delete user."""
    
    try:
        # Prevent self-deletion
        if user_id == current_user["id"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own account"
            )
        
        # Get user
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        username = user.username
        
        # Delete user (cascade will handle user_roles)
        await db.delete(user)
        await db.commit()
        
        # Log user deletion
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="delete",
            resource_type="user",
            resource_id=user_id,
            resource_name=username,
            success=True
        )
        
        logger.info(f"User {username} deleted by {current_user['username']}")
        
        return {"message": "User deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete user {user_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )


@router.get("/me/profile", response_model=UserResponse)
async def get_current_user_profile(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Get current user's profile."""
    
    try:
        result = await db.execute(
            select(User)
            .options(joinedload(User.roles).joinedload(UserRole.role))
            .options(joinedload(User.organization))
            .where(User.id == current_user["id"])
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return _format_user_response(user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user profile for {current_user['id']}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user profile"
        )


@router.put("/me/profile", response_model=UserResponse)
async def update_current_user_profile(
    profile_data: UserProfileUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Update current user's profile."""
    
    try:
        # Get user
        result = await db.execute(
            select(User)
            .options(joinedload(User.roles).joinedload(UserRole.role))
            .options(joinedload(User.organization))
            .where(User.id == current_user["id"])
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Check email uniqueness if changed
        if profile_data.email and profile_data.email != user.email:
            result = await db.execute(
                select(User).where(and_(User.email == profile_data.email, User.id != current_user["id"]))
            )
            if result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already exists"
                )
        
        # Update fields
        if profile_data.first_name is not None:
            user.first_name = profile_data.first_name
        if profile_data.last_name is not None:
            user.last_name = profile_data.last_name
        if profile_data.email is not None:
            user.email = profile_data.email
        
        user.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(user)
        
        # Log profile update
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="update_profile",
            resource_type="user",
            resource_id=user.id,
            resource_name=user.username,
            success=True,
            additional_data={
                "updated_fields": profile_data.dict(exclude_unset=True)
            }
        )
        
        logger.info(f"Profile updated for user {user.username}")
        
        # Get updated user with roles for response
        result = await db.execute(
            select(User)
            .options(joinedload(User.roles).joinedload(UserRole.role))
            .options(joinedload(User.organization))
            .where(User.id == user.id)
        )
        updated_user = result.scalar_one()
        
        return _format_user_response(updated_user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update profile for user {current_user['id']}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update profile"
        )


def _format_user_response(user: User) -> UserResponse:
    """Format user object as response model."""
    
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        full_name=user.full_name,
        status=user.status,
        organization_id=user.organization_id,
        organization_name=user.organization.name if user.organization else None,
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login_at=user.last_login_at,
        sso_id=user.sso_id,
        ldap_dn=user.ldap_dn,
        roles=[
            {
                "id": role.role.id,
                "name": role.role.name,
                "description": role.role.description
            }
            for role in user.roles
        ]
    ) 