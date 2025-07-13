"""
KubeNexus Authentication Service
FastAPI microservice for user authentication and authorization.
"""

import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
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
from routers import auth, users, health
from middleware import LoggingMiddleware, RateLimitMiddleware

settings = get_settings()
logger = init_logging("auth-service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Auth Service")
    try:
        await init_shared_services()
        logger.info("Auth Service started successfully")
        yield
    except Exception as e:
        logger.error(f"Failed to start Auth Service: {e}")
        raise
    finally:
        # Shutdown
        logger.info("Shutting down Auth Service")
        await cleanup_shared_services()
        logger.info("Auth Service shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="KubeNexus Authentication Service",
    description="Authentication and authorization service for KubeNexus platform",
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)


# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.backend_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure appropriately for production
)

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
    auth.router,
    prefix="/auth",
    tags=["Authentication"]
)

app.include_router(
    users.router,
    prefix="/users",
    tags=["User Management"]
)


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "KubeNexus Authentication Service",
        "version": settings.app_version,
        "status": "running",
        "docs": "/docs"
    }


# Development server
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.auth_service_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    ) 