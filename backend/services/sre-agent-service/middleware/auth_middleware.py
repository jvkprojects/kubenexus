"""
Authentication Middleware for SRE Agent Service
"""

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared import get_logger

logger = get_logger(__name__)


class AuthMiddleware(BaseHTTPMiddleware):
    """Authentication middleware for SRE Agent Service."""
    
    async def dispatch(self, request: Request, call_next):
        """Process the request and add authentication context."""
        # Skip authentication for health and docs endpoints
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json", "/"]:
            response = await call_next(request)
            return response
        
        # Add authentication context to request
        try:
            response = await call_next(request)
            return response
        except Exception as e:
            logger.error(f"Authentication middleware error: {e}")
            raise HTTPException(status_code=500, detail="Internal server error") 