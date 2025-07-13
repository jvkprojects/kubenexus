"""
KubeNexus Audit Log Router
Enterprise-level audit logging with compliance tracking and advanced filtering.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    AuditLog,
    User,
    get_current_user,
    require_permission
)

router = APIRouter()
logger = get_logger("audit-log-service")


class AuditLogCreate(BaseModel):
    """Schema for creating audit log entries."""
    action: str = Field(..., description="Action performed")
    resource_type: str = Field(..., description="Type of resource affected")
    resource_id: Optional[str] = Field(None, description="ID of the resource")
    resource_name: Optional[str] = Field(None, description="Name of the resource")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details")
    ip_address: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="Client user agent")
    status: str = Field(default="success", description="Status of the action")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class AuditLogResponse(BaseModel):
    """Schema for audit log response."""
    id: int
    user_id: int
    username: str
    action: str
    resource_type: str
    resource_id: Optional[str]
    resource_name: Optional[str]
    details: Optional[Dict[str, Any]]
    ip_address: Optional[str]
    user_agent: Optional[str]
    status: str
    metadata: Optional[Dict[str, Any]]
    timestamp: datetime

    class Config:
        from_attributes = True


class AuditLogFilter(BaseModel):
    """Schema for filtering audit logs."""
    user_id: Optional[int] = None
    username: Optional[str] = None
    action: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    status: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    ip_address: Optional[str] = None


class AuditLogStats(BaseModel):
    """Schema for audit log statistics."""
    total_logs: int
    success_count: int
    failure_count: int
    unique_users: int
    unique_actions: int
    date_range: Dict[str, datetime]


@router.post("/logs", response_model=AuditLogResponse)
async def create_audit_log(
    log_data: AuditLogCreate,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("audit_log:create"))
):
    """
    Create a new audit log entry.
    Requires 'audit_log:create' permission.
    """
    try:
        # Get user from current user info
        user_id = current_user.get("user_id")
        
        # Get user from database
        user_query = select(User).where(User.id == user_id)
        result = await db.execute(user_query)
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Extract IP address and user agent if not provided
        ip_address = log_data.ip_address or request.client.host
        user_agent = log_data.user_agent or request.headers.get("user-agent")
        
        # Create audit log entry
        audit_log = AuditLog(
            user_id=user_id,
            action=log_data.action,
            resource_type=log_data.resource_type,
            resource_id=log_data.resource_id,
            resource_name=log_data.resource_name,
            details=log_data.details,
            ip_address=ip_address,
            user_agent=user_agent,
            status=log_data.status,
            metadata=log_data.metadata
        )
        
        db.add(audit_log)
        await db.commit()
        await db.refresh(audit_log)
        
        # Prepare response
        response = AuditLogResponse(
            id=audit_log.id,
            user_id=audit_log.user_id,
            username=user.username,
            action=audit_log.action,
            resource_type=audit_log.resource_type,
            resource_id=audit_log.resource_id,
            resource_name=audit_log.resource_name,
            details=audit_log.details,
            ip_address=audit_log.ip_address,
            user_agent=audit_log.user_agent,
            status=audit_log.status,
            metadata=audit_log.metadata,
            timestamp=audit_log.timestamp
        )
        
        logger.info(f"Created audit log entry: {audit_log.id} for user: {user.username}")
        return response
        
    except Exception as e:
        logger.error(f"Error creating audit log: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    username: Optional[str] = Query(None, description="Filter by username"),
    action: Optional[str] = Query(None, description="Filter by action"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    start_date: Optional[datetime] = Query(None, description="Filter by start date"),
    end_date: Optional[datetime] = Query(None, description="Filter by end date"),
    ip_address: Optional[str] = Query(None, description="Filter by IP address"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("audit_log:read"))
):
    """
    Get audit logs with advanced filtering and pagination.
    Requires 'audit_log:read' permission.
    """
    try:
        # Build query with filters
        query = select(AuditLog, User).join(User, AuditLog.user_id == User.id)
        
        # Apply filters
        conditions = []
        
        if user_id:
            conditions.append(AuditLog.user_id == user_id)
        
        if username:
            conditions.append(User.username.ilike(f"%{username}%"))
        
        if action:
            conditions.append(AuditLog.action.ilike(f"%{action}%"))
        
        if resource_type:
            conditions.append(AuditLog.resource_type.ilike(f"%{resource_type}%"))
        
        if resource_id:
            conditions.append(AuditLog.resource_id == resource_id)
        
        if status:
            conditions.append(AuditLog.status == status)
        
        if start_date:
            conditions.append(AuditLog.timestamp >= start_date)
        
        if end_date:
            conditions.append(AuditLog.timestamp <= end_date)
        
        if ip_address:
            conditions.append(AuditLog.ip_address == ip_address)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Apply ordering and pagination
        query = query.order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit)
        
        result = await db.execute(query)
        logs_with_users = result.all()
        
        # Format response
        response = []
        for audit_log, user_info in logs_with_users:
            response.append(AuditLogResponse(
                id=audit_log.id,
                user_id=audit_log.user_id,
                username=user_info.username,
                action=audit_log.action,
                resource_type=audit_log.resource_type,
                resource_id=audit_log.resource_id,
                resource_name=audit_log.resource_name,
                details=audit_log.details,
                ip_address=audit_log.ip_address,
                user_agent=audit_log.user_agent,
                status=audit_log.status,
                metadata=audit_log.metadata,
                timestamp=audit_log.timestamp
            ))
        
        logger.info(f"Retrieved {len(response)} audit logs for user: {current_user.get('username')}")
        return response
        
    except Exception as e:
        logger.error(f"Error retrieving audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/logs/{log_id}", response_model=AuditLogResponse)
async def get_audit_log(
    log_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("audit_log:read"))
):
    """
    Get a specific audit log entry by ID.
    Requires 'audit_log:read' permission.
    """
    try:
        # Get audit log with user info
        query = select(AuditLog, User).join(User, AuditLog.user_id == User.id).where(AuditLog.id == log_id)
        result = await db.execute(query)
        log_with_user = result.first()
        
        if not log_with_user:
            raise HTTPException(status_code=404, detail="Audit log not found")
        
        audit_log, user_info = log_with_user
        
        response = AuditLogResponse(
            id=audit_log.id,
            user_id=audit_log.user_id,
            username=user_info.username,
            action=audit_log.action,
            resource_type=audit_log.resource_type,
            resource_id=audit_log.resource_id,
            resource_name=audit_log.resource_name,
            details=audit_log.details,
            ip_address=audit_log.ip_address,
            user_agent=audit_log.user_agent,
            status=audit_log.status,
            metadata=audit_log.metadata,
            timestamp=audit_log.timestamp
        )
        
        logger.info(f"Retrieved audit log: {log_id} for user: {current_user.get('username')}")
        return response
        
    except Exception as e:
        logger.error(f"Error retrieving audit log {log_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/stats", response_model=AuditLogStats)
async def get_audit_stats(
    start_date: Optional[datetime] = Query(None, description="Start date for statistics"),
    end_date: Optional[datetime] = Query(None, description="End date for statistics"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("audit_log:read"))
):
    """
    Get audit log statistics.
    Requires 'audit_log:read' permission.
    """
    try:
        # Set default date range if not provided
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)
        
        # Build base query with date filter
        base_query = select(AuditLog).where(
            and_(
                AuditLog.timestamp >= start_date,
                AuditLog.timestamp <= end_date
            )
        )
        
        # Get total count
        total_query = select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp >= start_date,
                AuditLog.timestamp <= end_date
            )
        )
        total_result = await db.execute(total_query)
        total_logs = total_result.scalar() or 0
        
        # Get success/failure counts
        success_query = select(func.count(AuditLog.id)).where(
            and_(
                AuditLog.timestamp >= start_date,
                AuditLog.timestamp <= end_date,
                AuditLog.status == "success"
            )
        )
        success_result = await db.execute(success_query)
        success_count = success_result.scalar() or 0
        
        failure_count = total_logs - success_count
        
        # Get unique users count
        unique_users_query = select(func.count(func.distinct(AuditLog.user_id))).where(
            and_(
                AuditLog.timestamp >= start_date,
                AuditLog.timestamp <= end_date
            )
        )
        unique_users_result = await db.execute(unique_users_query)
        unique_users = unique_users_result.scalar() or 0
        
        # Get unique actions count
        unique_actions_query = select(func.count(func.distinct(AuditLog.action))).where(
            and_(
                AuditLog.timestamp >= start_date,
                AuditLog.timestamp <= end_date
            )
        )
        unique_actions_result = await db.execute(unique_actions_query)
        unique_actions = unique_actions_result.scalar() or 0
        
        response = AuditLogStats(
            total_logs=total_logs,
            success_count=success_count,
            failure_count=failure_count,
            unique_users=unique_users,
            unique_actions=unique_actions,
            date_range={
                "start": start_date,
                "end": end_date
            }
        )
        
        logger.info(f"Retrieved audit stats for user: {current_user.get('username')}")
        return response
        
    except Exception as e:
        logger.error(f"Error retrieving audit stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/logs/{log_id}")
async def delete_audit_log(
    log_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("audit_log:delete"))
):
    """
    Delete an audit log entry (admin only).
    Requires 'audit_log:delete' permission.
    """
    try:
        # Find and delete audit log
        audit_log_query = select(AuditLog).where(AuditLog.id == log_id)
        result = await db.execute(audit_log_query)
        audit_log = result.scalar_one_or_none()
        
        if not audit_log:
            raise HTTPException(status_code=404, detail="Audit log not found")
        
        await db.delete(audit_log)
        await db.commit()
        
        logger.info(f"Deleted audit log: {log_id} by user: {current_user.get('username')}")
        return {"message": "Audit log deleted successfully"}
        
    except Exception as e:
        logger.error(f"Error deleting audit log {log_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/logs/bulk")
async def bulk_create_audit_logs(
    logs_data: List[AuditLogCreate],
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("audit_log:create"))
):
    """
    Create multiple audit log entries in bulk.
    Requires 'audit_log:create' permission.
    """
    try:
        # Get user from current user info
        user_id = current_user.get("user_id")
        
        # Validate bulk size
        if len(logs_data) > 1000:
            raise HTTPException(status_code=400, detail="Bulk creation limited to 1000 entries")
        
        # Extract IP address and user agent
        ip_address = request.client.host
        user_agent = request.headers.get("user-agent")
        
        # Create audit log entries
        audit_logs = []
        for log_data in logs_data:
            audit_log = AuditLog(
                user_id=user_id,
                action=log_data.action,
                resource_type=log_data.resource_type,
                resource_id=log_data.resource_id,
                resource_name=log_data.resource_name,
                details=log_data.details,
                ip_address=log_data.ip_address or ip_address,
                user_agent=log_data.user_agent or user_agent,
                status=log_data.status,
                metadata=log_data.metadata
            )
            audit_logs.append(audit_log)
        
        db.add_all(audit_logs)
        await db.commit()
        
        logger.info(f"Created {len(audit_logs)} audit log entries in bulk for user: {current_user.get('username')}")
        return {"message": f"Successfully created {len(audit_logs)} audit log entries"}
        
    except Exception as e:
        logger.error(f"Error creating bulk audit logs: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error") 