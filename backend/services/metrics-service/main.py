"""
KubeNexus Metrics Service
Service for collecting and exposing system metrics and performance data.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
from routers import health, metrics

settings = get_settings()
logger = init_logging("metrics-service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Metrics Service")
    try:
        await init_shared_services()
        logger.info("Metrics Service started successfully")
        yield
    finally:
        logger.info("Shutting down Metrics Service")
        await cleanup_shared_services()


app = FastAPI(
    title="KubeNexus Metrics Service",
    description="Service for collecting and exposing system metrics and performance data",
    version=settings.app_version,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.backend_cors_origins,
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(metrics.router, prefix="/metrics", tags=["Metrics"])


@app.get("/")
async def root():
    return {
        "service": "KubeNexus Metrics Service",
        "version": settings.app_version,
        "status": "running"
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=settings.metrics_service_port, reload=settings.debug) 