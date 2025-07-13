"""
Health check router for KubeNexus Cluster Manager Service.
Provides comprehensive health monitoring and service status endpoints.
"""

from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import asyncio
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    get_settings
)

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()


class HealthStatus(BaseModel):
    status: str
    timestamp: datetime
    service: str
    version: str


class DetailedHealthStatus(BaseModel):
    status: str
    timestamp: datetime
    service: str
    version: str
    dependencies: Dict[str, Dict[str, Any]]
    cluster_connections: Dict[str, Dict[str, Any]]


class ReadinessStatus(BaseModel):
    ready: bool
    timestamp: datetime
    checks: Dict[str, bool]


class LivenessStatus(BaseModel):
    alive: bool
    timestamp: datetime


class HealthMetrics(BaseModel):
    uptime: float
    memory_usage: Dict[str, Any]
    cluster_count: int
    active_connections: int
    request_metrics: Dict[str, Any]


@router.get("/", response_model=HealthStatus)
async def health_check():
    """Basic health check endpoint."""
    
    return HealthStatus(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        service="cluster-manager-service",
        version=settings.app_version
    )


@router.get("/detailed", response_model=DetailedHealthStatus)
async def detailed_health_check(
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Detailed health check with dependency status."""
    
    timestamp = datetime.now(timezone.utc)
    dependencies = {}
    cluster_connections = {}
    overall_status = "healthy"
    
    try:
        # Check database connection
        try:
            await db.execute(text("SELECT 1"))
            dependencies["database"] = {
                "status": "healthy",
                "response_time_ms": 0,  # Would measure actual time in production
                "details": "PostgreSQL connection successful"
            }
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            dependencies["database"] = {
                "status": "unhealthy",
                "error": str(e),
                "details": "Failed to connect to PostgreSQL"
            }
            overall_status = "degraded"
        
        # Redis check temporarily disabled
        dependencies["redis"] = {
            "status": "skipped",
            "details": "Redis health check temporarily disabled"
        }
        
        # Check Auth Service connectivity
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{settings.auth_service_url}/health")
                if response.status_code == 200:
                    dependencies["auth_service"] = {
                        "status": "healthy",
                        "response_time_ms": 0,
                        "details": "Auth service reachable"
                    }
                else:
                    dependencies["auth_service"] = {
                        "status": "unhealthy",
                        "details": f"Auth service returned {response.status_code}"
                    }
                    overall_status = "degraded"
        except Exception as e:
            logger.error(f"Auth service health check failed: {e}")
            dependencies["auth_service"] = {
                "status": "unhealthy",
                "error": str(e),
                "details": "Failed to reach auth service"
            }
            overall_status = "degraded"
        
        # Check cluster connections (mock implementation)
        try:
            # In a real implementation, this would check actual Kubernetes API connectivity
            cluster_connections["sample_cluster"] = {
                "status": "healthy",
                "cluster_type": "EKS",
                "region": "us-west-2",
                "nodes": 3,
                "version": "1.28.2",
                "last_check": timestamp.isoformat()
            }
        except Exception as e:
            logger.error(f"Cluster connectivity check failed: {e}")
            cluster_connections["error"] = {
                "status": "error",
                "details": str(e)
            }
            overall_status = "degraded"
        
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        overall_status = "unhealthy"
    
    return DetailedHealthStatus(
        status=overall_status,
        timestamp=timestamp,
        service="cluster-manager-service",
        version=settings.app_version,
        dependencies=dependencies,
        cluster_connections=cluster_connections
    )


@router.get("/ready", response_model=ReadinessStatus)
async def readiness_check(
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Kubernetes readiness probe endpoint."""
    
    checks = {}
    
    try:
        # Database readiness
        await db.execute(text("SELECT 1"))
        checks["database"] = True
    except:
        checks["database"] = False
    
    # Redis check temporarily disabled
    checks["redis"] = True  # Assume healthy for now
    
    # Service is ready if all critical components are available
    is_ready = all([
        checks.get("database", False),
        checks.get("redis", False)
    ])
    
    status_code = status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE
    
    if not is_ready:
        raise HTTPException(status_code=status_code, detail="Service not ready")
    
    return ReadinessStatus(
        ready=is_ready,
        timestamp=datetime.now(timezone.utc),
        checks=checks
    )


@router.get("/live", response_model=LivenessStatus)
async def liveness_check():
    """Kubernetes liveness probe endpoint."""
    
    # Simple liveness check - if we can respond, we're alive
    return LivenessStatus(
        alive=True,
        timestamp=datetime.now(timezone.utc)
    )


@router.get("/metrics", response_model=HealthMetrics)
async def health_metrics(
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Service metrics endpoint for monitoring."""
    
    try:
        import psutil
        import time
        
        # Get memory usage
        process = psutil.Process()
        memory_info = process.memory_info()
        memory_usage = {
            "rss": memory_info.rss,
            "vms": memory_info.vms,
            "percent": process.memory_percent()
        }
        
        # Calculate uptime (mock)
        uptime = time.time() - 0  # Would track actual start time
        
        # Get cluster count from database
        try:
            result = await db.execute(text("SELECT COUNT(*) FROM clusters"))
            cluster_count = result.scalar() or 0
        except:
            cluster_count = 0
        
        # Mock active connections and request metrics
        active_connections = 5  # Would track real connections
        request_metrics = {
            "total_requests": 1000,
            "requests_per_minute": 50,
            "average_response_time": 150,
            "error_rate": 0.01
        }
        
        return HealthMetrics(
            uptime=uptime,
            memory_usage=memory_usage,
            cluster_count=cluster_count,
            active_connections=active_connections,
            request_metrics=request_metrics
        )
        
    except Exception as e:
        logger.error(f"Failed to collect metrics: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to collect service metrics"
        ) 