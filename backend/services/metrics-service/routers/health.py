"""Health check router for Metrics Service."""

from datetime import datetime, timezone
from fastapi import APIRouter
from pydantic import BaseModel
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from shared import get_settings

router = APIRouter()
settings = get_settings()

class HealthStatus(BaseModel):
    status: str
    timestamp: datetime
    service: str
    version: str

@router.get("/", response_model=HealthStatus)
async def health_check():
    return HealthStatus(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        service="metrics-service",
        version=settings.app_version
    ) 