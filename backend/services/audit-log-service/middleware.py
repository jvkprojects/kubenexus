"""
Middleware for KubeNexus Audit Log Service.
Handles logging, rate limiting, and request processing.
"""

import time
import json
from typing import Callable
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_logger,
    get_settings,
    get_redis_client,
    performance_logger,
    audit_logger
)

logger = get_logger(__name__)
settings = get_settings()


class LoggingMiddleware(BaseHTTPMiddleware):
    """Logging middleware for request/response tracking."""
    
    def __init__(self, app):
        super().__init__(app)
        self.logger = get_logger("audit_log_middleware")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process requests with logging."""
        start_time = time.time()
        
        # Log incoming request
        self.logger.info(
            "Request received",
            extra={
                "method": request.method,
                "url": str(request.url),
                "client_ip": request.client.host if request.client else "unknown",
                "user_agent": request.headers.get("user-agent", "unknown")
            }
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate processing time
            process_time = time.time() - start_time
            
            # Log response
            self.logger.info(
                "Request completed",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "status_code": response.status_code,
                    "process_time": round(process_time, 4),
                    "response_size": response.headers.get("content-length", "unknown")
                }
            )
            
            # Add processing time header
            response.headers["X-Process-Time"] = str(round(process_time, 4))
            
            return response
            
        except Exception as e:
            # Calculate processing time for errors
            process_time = time.time() - start_time
            
            # Log error
            self.logger.error(
                "Request failed",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "error": str(e),
                    "process_time": round(process_time, 4)
                },
                exc_info=True
            )
            
            raise


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware to prevent abuse."""
    
    def __init__(self, app):
        super().__init__(app)
        self.redis_client = get_redis_client()
        self.rate_limit = getattr(settings, 'rate_limit_per_minute', 100)
        self.logger = get_logger("audit_rate_limit")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply rate limiting based on client IP."""
        
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        if client_ip == "unknown":
            return await call_next(request)
        
        # Create rate limit key
        rate_limit_key = f"audit_rate_limit:{client_ip}"
        
        try:
            # Check current request count
            current_requests = await self.redis_client.get(rate_limit_key)
            
            if current_requests is None:
                # First request from this IP
                await self.redis_client.setex(rate_limit_key, 60, 1)
                return await call_next(request)
            
            current_count = int(current_requests)
            
            if current_count >= self.rate_limit:
                self.logger.warning(
                    "Rate limit exceeded",
                    extra={
                        "client_ip": client_ip,
                        "current_count": current_count,
                        "limit": self.rate_limit,
                        "url": str(request.url)
                    }
                )
                
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Please try again later."
                )
            
            # Increment counter
            await self.redis_client.incr(rate_limit_key)
            
            return await call_next(request)
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Rate limiting error: {e}")
            # Continue without rate limiting on Redis errors
            return await call_next(request)


class AuditTrackingMiddleware(BaseHTTPMiddleware):
    """Middleware to track audit log operations."""
    
    def __init__(self, app):
        super().__init__(app)
        self.logger = get_logger("audit_tracking")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Track audit log operations."""
        
        # Skip tracking for non-audit operations
        if not any(path in request.url.path for path in ["/audit", "/logs"]):
            return await call_next(request)
        
        start_time = time.time()
        
        try:
            # Extract user information if available
            user_id = getattr(request.state, 'user_id', 'anonymous')
            
            # Process request
            response = await call_next(request)
            
            # Log audit operation
            audit_logger.info(
                "Audit log operation",
                extra={
                    "user_id": user_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration": round(time.time() - start_time, 4),
                    "client_ip": request.client.host if request.client else "unknown"
                }
            )
            
            return response
            
        except Exception as e:
            # Log failed audit operation
            audit_logger.error(
                "Audit log operation failed",
                extra={
                    "user_id": getattr(request.state, 'user_id', 'anonymous'),
                    "method": request.method,
                    "path": request.url.path,
                    "error": str(e),
                    "duration": round(time.time() - start_time, 4)
                }
            )
            raise


class HealthCheckMiddleware(BaseHTTPMiddleware):
    """Middleware for health check optimization."""
    
    def __init__(self, app):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Optimize health check requests."""
        
        # Quick response for health checks
        if request.url.path == "/health":
            return Response(
                content='{"status": "healthy", "service": "audit-log-service"}',
                media_type="application/json",
                status_code=200
            )
        
        return await call_next(request)


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Middleware for request validation and sanitization."""
    
    def __init__(self, app):
        super().__init__(app)
        self.logger = get_logger("audit_validation")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Validate and sanitize requests."""
        
        # Validate content length
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                max_size = getattr(settings, 'max_upload_size', 10 * 1024 * 1024)  # 10MB default
                
                if length > max_size:
                    self.logger.warning(
                        "Request too large",
                        extra={
                            "content_length": length,
                            "max_allowed": max_size,
                            "url": str(request.url)
                        }
                    )
                    
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Request entity too large"
                    )
            except ValueError:
                pass
        
        # Validate content type for POST/PUT requests
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            if content_type and not content_type.startswith(("application/json", "application/x-www-form-urlencoded")):
                self.logger.warning(
                    "Invalid content type",
                    extra={
                        "content_type": content_type,
                        "method": request.method,
                        "url": str(request.url)
                    }
                )
        
        return await call_next(request) 