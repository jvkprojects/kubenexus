"""
KubeNexus Audit Log Service
Centralized audit logging for tracking user actions and system events.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_settings, 
    init_shared_services, 
    cleanup_shared_services,
    init_logging,
    get_logger
)
from routers import health, audit_logs

settings = get_settings()
logger = init_logging("audit-log-service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Audit Log Service")
    try:
        await init_shared_services()
        logger.info("Audit Log Service started successfully")
        yield
    finally:
        logger.info("Shutting down Audit Log Service")
        await cleanup_shared_services()


app = FastAPI(
    title="KubeNexus Audit Log Service",
    description="Centralized audit logging for tracking user actions and system events",
    version=settings.app_version,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.backend_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(audit_logs.router, prefix="/audit", tags=["Audit Logs"])


@app.get("/")
async def root():
    return {
        "service": "KubeNexus Audit Log Service",
        "version": settings.app_version,
        "status": "running"
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=settings.audit_log_service_port, reload=settings.debug) 