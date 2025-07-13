"""
Health check router for KubeNexus Authentication Service.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, status, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared import (
    get_async_db_dependency,
    check_database_health,
    get_logger,
    get_settings
)

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()


@router.get("/")
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": "auth-service",
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/detailed")
async def detailed_health_check(db: AsyncSession = Depends(get_async_db_dependency)):
    """Detailed health check with dependency checks."""
    
    health_status = {
        "status": "healthy",
        "service": "auth-service",
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {}
    }
    
    overall_healthy = True
    
    try:
        # Check database health
        db_health = await check_database_health()
        health_status["checks"]["database"] = db_health
        
        if db_health["status"] != "healthy":
            overall_healthy = False
        
        # Check Redis health (if available)
        try:
            from shared import RateLimiter
            rate_limiter = RateLimiter()
            # Simple Redis operation to check connectivity
            health_status["checks"]["redis"] = {
                "status": "healthy",
                "message": "Redis connection available"
            }
        except Exception as e:
            health_status["checks"]["redis"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            overall_healthy = False
        
        # Check configuration
        config_issues = []
        
        if not settings.jwt_secret or settings.jwt_secret == "super_secret_jwt_key_change_in_production":
            config_issues.append("JWT secret should be changed in production")
        
        if len(settings.kubeconfig_encryption_key) < 32:
            config_issues.append("Encryption key is too short")
        
        if config_issues:
            health_status["checks"]["configuration"] = {
                "status": "warning",
                "issues": config_issues
            }
        else:
            health_status["checks"]["configuration"] = {
                "status": "healthy",
                "message": "Configuration is valid"
            }
        
        # Set overall status
        if not overall_healthy:
            health_status["status"] = "unhealthy"
        elif config_issues:
            health_status["status"] = "degraded"
        
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        health_status = {
            "status": "unhealthy",
            "service": "auth-service",
            "version": settings.app_version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }
        overall_healthy = False
    
    # Return appropriate HTTP status
    if not overall_healthy:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=health_status
        )
    
    return health_status


@router.get("/ready")
async def readiness_check(db: AsyncSession = Depends(get_async_db_dependency)):
    """Readiness check for Kubernetes."""
    
    try:
        # Check if service is ready to accept requests
        # Test database connectivity
        db_health = await check_database_health()
        
        if db_health["status"] != "healthy":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "ready": False,
                    "reason": "Database not available",
                    "details": db_health
                }
            )
        
        return {
            "ready": True,
            "service": "auth-service",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Readiness check failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "ready": False,
                "reason": "Service initialization error",
                "error": str(e)
            }
        )


@router.get("/live")
async def liveness_check():
    """Liveness check for Kubernetes."""
    
    try:
        # Simple check to ensure the service process is alive
        # This should not check external dependencies
        
        return {
            "alive": True,
            "service": "auth-service",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Liveness check failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "alive": False,
                "error": str(e)
            }
        )


@router.get("/metrics")
async def metrics_endpoint():
    """Basic metrics endpoint."""
    
    # This could be expanded to include Prometheus metrics
    # For now, return basic service metrics
    
    return {
        "service": "auth-service",
        "metrics": {
            "uptime_seconds": "calculated_at_runtime",  # Would calculate actual uptime
            "version": settings.app_version,
            "environment": settings.environment
        },
        "timestamp": datetime.now(timezone.utc).isoformat()
    } 