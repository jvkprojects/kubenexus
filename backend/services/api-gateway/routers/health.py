"""
Health check router for KubeNexus API Gateway.
Provides health monitoring for the gateway and backend services.
"""

from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter
from pydantic import BaseModel
import httpx
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import get_logger, get_settings

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()


class HealthStatus(BaseModel):
    status: str
    timestamp: datetime
    service: str
    version: str


class GatewayHealth(BaseModel):
    gateway: HealthStatus
    backend_services: Dict[str, Dict[str, Any]]


@router.get("/", response_model=HealthStatus)
async def health_check():
    """Basic health check endpoint."""
    
    return HealthStatus(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        service="api-gateway",
        version=settings.app_version
    )


@router.get("/detailed", response_model=GatewayHealth)
async def detailed_health_check():
    """Detailed health check including backend services."""
    
    gateway_health = HealthStatus(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        service="api-gateway",
        version=settings.app_version
    )
    
    # Check backend services
    services = {
        "auth-service": settings.auth_service_url,
        "cluster-manager-service": settings.cluster_manager_service_url,
        "sre-agent-service": settings.sre_agent_service_url,
        "audit-log-service": settings.audit_log_service_url,
        "metrics-service": settings.metrics_service_url,
        "terminal-service": settings.terminal_service_url
    }
    
    backend_services = {}
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        for service_name, service_url in services.items():
            try:
                response = await client.get(f"{service_url}/health")
                backend_services[service_name] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "url": service_url,
                    "response_time_ms": response.elapsed.total_seconds() * 1000
                }
            except Exception as e:
                backend_services[service_name] = {
                    "status": "unreachable",
                    "url": service_url,
                    "error": str(e)
                }
    
    return GatewayHealth(
        gateway=gateway_health,
        backend_services=backend_services
    ) 