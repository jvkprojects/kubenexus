"""
Proxy router for KubeNexus API Gateway.
Additional proxy endpoints and service routing logic.
"""

from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import JSONResponse
import httpx
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import get_logger, get_settings

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()


@router.get("/status")
async def proxy_status():
    """Get proxy routing status and configuration."""
    
    return {
        "proxy_status": "active",
        "service_routes": {
            "/api/v1/auth": settings.auth_service_url,
            "/api/v1/users": settings.auth_service_url,
            "/api/v1/clusters": settings.cluster_manager_service_url,
            "/api/v1/cloud-providers": settings.cluster_manager_service_url,
            "/api/v1/kubeconfig": settings.cluster_manager_service_url,
            "/api/v1/sre": settings.sre_agent_service_url,
            "/api/v1/audit": settings.audit_log_service_url,
            "/api/v1/metrics": settings.metrics_service_url,
            "/api/v1/terminal": settings.terminal_service_url
        },
        "middleware_order": [
            "ProxyMiddleware",
            "RBACMiddleware", 
            "AuthenticationMiddleware",
            "LoggingMiddleware",
            "RateLimitMiddleware"
        ]
    }


@router.get("/services/health")
async def services_health():
    """Get health status of all backend services."""
    
    services = {
        "auth-service": settings.auth_service_url,
        "cluster-manager-service": settings.cluster_manager_service_url,
        "sre-agent-service": settings.sre_agent_service_url,
        "audit-log-service": settings.audit_log_service_url,
        "metrics-service": settings.metrics_service_url,
        "terminal-service": settings.terminal_service_url
    }
    
    service_health = {}
    overall_healthy = True
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        for service_name, service_url in services.items():
            try:
                response = await client.get(f"{service_url}/health")
                is_healthy = response.status_code == 200
                service_health[service_name] = {
                    "status": "healthy" if is_healthy else "unhealthy",
                    "url": service_url,
                    "response_time_ms": response.elapsed.total_seconds() * 1000,
                    "last_check": "now"
                }
                if not is_healthy:
                    overall_healthy = False
            except Exception as e:
                service_health[service_name] = {
                    "status": "unreachable",
                    "url": service_url,
                    "error": str(e),
                    "last_check": "now"
                }
                overall_healthy = False
    
    return {
        "overall_status": "healthy" if overall_healthy else "degraded",
        "services": service_health,
        "total_services": len(services),
        "healthy_services": sum(1 for s in service_health.values() if s["status"] == "healthy"),
        "timestamp": "now"
    } 