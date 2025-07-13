"""
Health check router for KubeNexus SRE Agent Service.
"""

from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
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
    ml_models: Dict[str, Dict[str, Any]]
    monitoring_status: Dict[str, Any]


@router.get("/", response_model=HealthStatus)
async def health_check():
    """Basic health check endpoint."""
    
    return HealthStatus(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        service="sre-agent-service",
        version=settings.app_version
    )


@router.get("/detailed", response_model=DetailedHealthStatus)
async def detailed_health_check(
    db: AsyncSession = Depends(get_async_db_dependency)
):
    """Detailed health check with ML models and monitoring status."""
    
    timestamp = datetime.now(timezone.utc)
    dependencies = {}
    ml_models = {}
    monitoring_status = {}
    overall_status = "healthy"
    
    try:
        # Check database connection
        try:
            await db.execute(text("SELECT 1"))
            dependencies["database"] = {
                "status": "healthy",
                "details": "PostgreSQL connection successful"
            }
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            dependencies["database"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            overall_status = "degraded"
        
        # Check Redis connection (simplified)
        try:
            import redis
            redis_client = redis.from_url(settings.redis_url, decode_responses=True)
            redis_client.ping()
            dependencies["redis"] = {
                "status": "healthy",
                "details": "Redis connection successful"
            }
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            dependencies["redis"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            overall_status = "degraded"
        
        # Check ML models status
        try:
            from services.ml_service import MLService
            model_status = await MLService.get_model_status()
            ml_models = model_status
            
            if not all(model.get("status") == "loaded" for model in model_status.values()):
                overall_status = "degraded"
                
        except Exception as e:
            logger.warning(f"ML models health check failed: {e}")
            ml_models["ml_service"] = {"status": "warning", "details": "ML service initialization in progress"}
        
        # Check monitoring status
        try:
            from services.monitoring_service import MonitoringService
            monitoring_status = await MonitoringService.get_monitoring_status()
        except Exception as e:
            logger.warning(f"Monitoring status check failed: {e}")
            monitoring_status = {"status": "warning", "details": "Monitoring service initialization in progress"}
        
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        overall_status = "unhealthy"
    
    return DetailedHealthStatus(
        status=overall_status,
        timestamp=timestamp,
        service="sre-agent-service",
        version=settings.app_version,
        dependencies=dependencies,
        ml_models=ml_models,
        monitoring_status=monitoring_status
    ) 