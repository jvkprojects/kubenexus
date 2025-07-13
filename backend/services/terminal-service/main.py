"""
KubeNexus Terminal Service
Web-based terminal service for kubectl access to Kubernetes clusters.
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
from routers import health, terminal

settings = get_settings()
logger = init_logging("terminal-service")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Terminal Service")
    try:
        await init_shared_services()
        logger.info("Terminal Service started successfully")
        yield
    finally:
        logger.info("Shutting down Terminal Service")
        await cleanup_shared_services()


app = FastAPI(
    title="KubeNexus Terminal Service",
    description="Web-based terminal service for kubectl access to Kubernetes clusters",
    version=settings.app_version,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.backend_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(terminal.router, prefix="/terminal", tags=["Terminal"])


@app.get("/")
async def root():
    return {
        "service": "KubeNexus Terminal Service",
        "version": settings.app_version,
        "status": "running"
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=settings.terminal_service_port, reload=settings.debug) 