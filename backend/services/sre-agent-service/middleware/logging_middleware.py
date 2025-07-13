"""
Logging Middleware for SRE Agent Service
"""

import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared import get_logger

logger = get_logger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Logging middleware for SRE Agent Service."""
    
    async def dispatch(self, request: Request, call_next):
        """Process the request and log relevant information."""
        start_time = time.time()
        
        # Log incoming request
        logger.info(f"Request: {request.method} {request.url.path}", extra={
            "method": request.method,
            "path": request.url.path,
            "query_params": str(request.query_params),
            "client_ip": request.client.host if request.client else "unknown"
        })
        
        try:
            response = await call_next(request)
            
            # Calculate processing time
            process_time = time.time() - start_time
            
            # Log response
            logger.info(f"Response: {response.status_code} for {request.method} {request.url.path}", extra={
                "status_code": response.status_code,
                "processing_time": process_time,
                "method": request.method,
                "path": request.url.path
            })
            
            # Add processing time to response headers
            response.headers["X-Process-Time"] = str(process_time)
            
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            logger.error(f"Request failed: {request.method} {request.url.path} - {str(e)}", extra={
                "method": request.method,
                "path": request.url.path,
                "processing_time": process_time,
                "error": str(e)
            })
            raise 