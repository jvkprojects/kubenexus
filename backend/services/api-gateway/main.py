"""
KubeNexus API Gateway Service
Central API gateway for routing requests to microservices with RBAC enforcement.
"""

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
import httpx
import uvicorn

# Import shared utilities
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_settings, 
    init_shared_services, 
    cleanup_shared_services,
    init_logging,
    get_logger,
    AuthenticationError,
    AuthorizationError
)
from middleware import (
    AuthenticationMiddleware,
    RBACMiddleware,
    LoggingMiddleware,
    RateLimitMiddleware,
    ProxyMiddleware
)
from routers import health, proxy

settings = get_settings()
logger = init_logging("api-gateway")
security = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting API Gateway")
    try:
        await init_shared_services()
        logger.info("API Gateway started successfully")
        yield
    except Exception as e:
        logger.error(f"Failed to start API Gateway: {e}")
        raise
    finally:
        # Shutdown
        logger.info("Shutting down API Gateway")
        await cleanup_shared_services()
        logger.info("API Gateway shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="KubeNexus API Gateway",
    description="Central API gateway with authentication, authorization, and service routing",
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)


# Add middleware (order is important - first added is outermost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.backend_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure appropriately for production
)

# Apply custom middleware
app.add_middleware(ProxyMiddleware)
app.add_middleware(RBACMiddleware)  
app.add_middleware(AuthenticationMiddleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware)


# Exception handlers
@app.exception_handler(AuthenticationError)
async def authentication_exception_handler(request: Request, exc: AuthenticationError):
    """Handle authentication errors."""
    logger.warning(f"Authentication error: {exc.detail}", extra={"request_url": str(request.url)})
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "type": "authentication_error"}
    )


@app.exception_handler(AuthorizationError)
async def authorization_exception_handler(request: Request, exc: AuthorizationError):
    """Handle authorization errors."""
    logger.warning(f"Authorization error: {exc.detail}", extra={"request_url": str(request.url)})
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "type": "authorization_error"}
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    logger.warning(f"HTTP error: {exc.detail}", extra={
        "status_code": exc.status_code,
        "request_url": str(request.url)
    })
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True, extra={
        "request_url": str(request.url)
    })
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )


# Include routers
app.include_router(
    health.router,
    prefix="/health",
    tags=["Health Check"]
)

app.include_router(
    proxy.router,
    prefix="/api/v1",
    tags=["Service Proxy"]
)


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "KubeNexus API Gateway",
        "version": settings.app_version,
        "status": "running",
        "docs": "/docs",
        "services": {
            "auth": f"{settings.auth_service_url}",
            "cluster_manager": f"{settings.cluster_manager_service_url}",
            "sre_agent": f"{settings.sre_agent_service_url}",
            "audit_log": f"{settings.audit_log_service_url}",
            "metrics": f"{settings.metrics_service_url}",
            "terminal": f"{settings.terminal_service_url}"
        }
    }


# Service discovery endpoint
@app.get("/services")
async def get_services():
    """Get available services and their health status."""
    
    services = {
        "auth-service": settings.auth_service_url,
        "cluster-manager-service": settings.cluster_manager_service_url,
        "sre-agent-service": settings.sre_agent_service_url,
        "audit-log-service": settings.audit_log_service_url,
        "metrics-service": settings.metrics_service_url,
        "terminal-service": settings.terminal_service_url
    }
    
    service_status = {}
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        for service_name, service_url in services.items():
            try:
                response = await client.get(f"{service_url}/health")
                service_status[service_name] = {
                    "url": service_url,
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "response_time_ms": response.elapsed.total_seconds() * 1000
                }
            except Exception as e:
                service_status[service_name] = {
                    "url": service_url,
                    "status": "unreachable",
                    "error": str(e)
                }
    
    return service_status


# Development server
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.api_gateway_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    ) 