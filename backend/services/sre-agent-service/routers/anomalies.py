"""
Anomalies router for KubeNexus SRE Agent Service.
Handles anomaly detection and management endpoints.
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, Field
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    ProblemApplication,
    KubernetesCluster,
    audit_logger,
    require_permissions,
    get_current_user
)
from services.ml_service import MLService

router = APIRouter()
logger = get_logger(__name__)


# Pydantic models
class AnomalyDetectionRequest(BaseModel):
    cluster_id: UUID
    metrics_data: Dict[str, Any]
    time_window_minutes: Optional[int] = Field(default=15, ge=1, le=1440)


class AnomalyResponse(BaseModel):
    id: UUID
    cluster_id: UUID
    cluster_name: str
    anomaly_type: str
    severity: str
    confidence_score: float
    description: str
    detected_at: datetime
    metrics_snapshot: Dict[str, Any]
    affected_resources: List[Dict[str, str]]


class AnomalyListResponse(BaseModel):
    anomalies: List[AnomalyResponse]
    total_count: int
    page: int
    page_size: int


@router.post("/detect", response_model=Dict[str, Any])
async def detect_anomalies(
    request: AnomalyDetectionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.anomalies.detect"))
):
    """Detect anomalies in cluster metrics."""
    
    try:
        # Verify cluster exists and user has access
        result = await db.execute(
            select(KubernetesCluster).where(KubernetesCluster.id == request.cluster_id)
        )
        cluster = result.scalar_one_or_none()
        
        if not cluster:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cluster not found"
            )
        
        # Run anomaly detection
        detection_result = await MLService.detect_anomalies(request.metrics_data)
        
        # Log the detection attempt
        audit_logger.info(
            "Anomaly detection performed",
            extra={
                "user_id": current_user["id"],
                "cluster_id": str(request.cluster_id),
                "anomalies_detected": len(detection_result.get("anomalies", []))
            }
        )
        
        return {
            "cluster_id": str(request.cluster_id),
            "detection_timestamp": datetime.now(timezone.utc).isoformat(),
            "anomalies_detected": len(detection_result.get("anomalies", [])),
            "anomalies": detection_result.get("anomalies", []),
            "confidence": detection_result.get("confidence", 0.0),
            "message": detection_result.get("message", "Anomaly detection completed")
        }
        
    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Anomaly detection failed: {str(e)}"
        )


@router.get("/", response_model=AnomalyListResponse)
async def list_anomalies(
    cluster_id: Optional[UUID] = Query(None, description="Filter by cluster ID"),
    severity: Optional[str] = Query(None, regex="^(critical|high|medium|low)$"),
    resolved: Optional[bool] = Query(None, description="Filter by resolution status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.anomalies.list"))
):
    """List detected anomalies with filtering and pagination."""
    
    try:
        # Build query
        query = select(ProblemApplication).options(
            joinedload(ProblemApplication.cluster)
        )
        
        # Apply filters
        conditions = []
        if cluster_id:
            conditions.append(ProblemApplication.cluster_id == cluster_id)
        if severity:
            conditions.append(ProblemApplication.severity == severity)
        if resolved is not None:
            if resolved:
                conditions.append(ProblemApplication.resolved_at.isnot(None))
            else:
                conditions.append(ProblemApplication.resolved_at.is_(None))
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Count total items
        count_query = select(func.count(ProblemApplication.id))
        if conditions:
            count_query = count_query.where(and_(*conditions))
        
        total_result = await db.execute(count_query)
        total_count = total_result.scalar()
        
        # Apply pagination
        offset = (page - 1) * page_size
        query = query.offset(offset).limit(page_size)
        query = query.order_by(ProblemApplication.detected_at.desc())
        
        # Execute query
        result = await db.execute(query)
        problems = result.scalars().all()
        
        # Convert to response format
        anomalies = []
        for problem in problems:
            anomaly = AnomalyResponse(
                id=problem.id,
                cluster_id=problem.cluster_id,
                cluster_name=problem.cluster.name,
                anomaly_type=problem.problem_type,
                severity=problem.severity,
                confidence_score=0.8,  # TODO: Store actual confidence score
                description=problem.problem_description,
                detected_at=problem.detected_at,
                metrics_snapshot=problem.detection_data or {},
                affected_resources=[{
                    "type": problem.resource_type,
                    "name": problem.resource_name,
                    "namespace": problem.namespace
                }]
            )
            anomalies.append(anomaly)
        
        return AnomalyListResponse(
            anomalies=anomalies,
            total_count=total_count,
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        logger.error(f"Failed to list anomalies: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list anomalies: {str(e)}"
        )


@router.get("/{anomaly_id}", response_model=AnomalyResponse)
async def get_anomaly(
    anomaly_id: UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.anomalies.read"))
):
    """Get detailed information about a specific anomaly."""
    
    try:
        result = await db.execute(
            select(ProblemApplication)
            .options(joinedload(ProblemApplication.cluster))
            .where(ProblemApplication.id == anomaly_id)
        )
        problem = result.scalar_one_or_none()
        
        if not problem:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Anomaly not found"
            )
        
        return AnomalyResponse(
            id=problem.id,
            cluster_id=problem.cluster_id,
            cluster_name=problem.cluster.name,
            anomaly_type=problem.problem_type,
            severity=problem.severity,
            confidence_score=0.8,  # TODO: Store actual confidence score
            description=problem.problem_description,
            detected_at=problem.detected_at,
            metrics_snapshot=problem.detection_data or {},
            affected_resources=[{
                "type": problem.resource_type,
                "name": problem.resource_name,
                "namespace": problem.namespace
            }]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get anomaly: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get anomaly: {str(e)}"
        )


@router.post("/{anomaly_id}/acknowledge")
async def acknowledge_anomaly(
    anomaly_id: UUID,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permissions("sre.anomalies.acknowledge"))
):
    """Acknowledge an anomaly (mark as reviewed)."""
    
    try:
        result = await db.execute(
            select(ProblemApplication).where(ProblemApplication.id == anomaly_id)
        )
        problem = result.scalar_one_or_none()
        
        if not problem:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Anomaly not found"
            )
        
        # Update acknowledgment
        problem.resolved_by = current_user["id"]
        # Note: We might want to add an 'acknowledged_at' field to the model
        
        await db.commit()
        
        audit_logger.info(
            "Anomaly acknowledged",
            extra={
                "user_id": current_user["id"],
                "anomaly_id": str(anomaly_id),
                "cluster_id": str(problem.cluster_id)
            }
        )
        
        return {"message": "Anomaly acknowledged successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to acknowledge anomaly: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to acknowledge anomaly: {str(e)}"
        ) 