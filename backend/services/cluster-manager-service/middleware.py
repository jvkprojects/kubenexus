"""
Middleware for KubeNexus Cluster Manager Service.
Handles authentication, logging, rate limiting, and security headers.
"""

import time
from typing import Callable, Dict, Any, Optional
from fastapi import Request, Response, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import httpx
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_logger,
    get_settings,
    TokenManager,
    RateLimiter,
    performance_log
)

logger = get_logger(__name__)
settings = get_settings()
security = HTTPBearer(auto_error=False)


class AuthMiddleware(BaseHTTPMiddleware):
    """Authentication middleware for validating JWT tokens."""
    
    def __init__(self, app):
        super().__init__(app)
        self.excluded_paths = ["/health", "/docs", "/redoc", "/openapi.json", "/"]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process authentication for incoming requests."""
        
        # Skip authentication for excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)
        
        try:
            # Get authorization header
            authorization = request.headers.get("authorization")
            if not authorization or not authorization.startswith("Bearer "):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Missing or invalid authorization header"
                )
            
            token = authorization.replace("Bearer ", "")
            
            # Verify token with auth service
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.get(
                        f"{settings.auth_service_url}/auth/verify",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10.0
                    )
                    
                    if response.status_code != 200:
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid token"
                        )
                    
                    user_data = response.json()
                    
                    # Add user context to request state
                    request.state.current_user = user_data
                    request.state.user_id = user_data["id"]
                    request.state.username = user_data["username"]
                    
                except httpx.RequestError:
                    logger.error("Failed to verify token with auth service")
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Authentication service unavailable"
                    )
            
            response = await call_next(request)
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authentication middleware error: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication error"
            )


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging HTTP requests and responses."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request and response details."""
        
        start_time = time.time()
        
        # Log request
        user_id = getattr(request.state, 'user_id', 'anonymous')
        logger.info(
            "Request started",
            extra={
                "method": request.method,
                "url": str(request.url),
                "user_id": user_id,
                "client_ip": request.client.host if request.client else "unknown"
            }
        )
        
        # Process request
        try:
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Log response
            logger.info(
                "Request completed",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "status_code": response.status_code,
                    "duration": duration,
                    "user_id": user_id
                }
            )
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "Request failed",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "duration": duration,
                    "user_id": user_id,
                    "error": str(e)
                },
                exc_info=True
            )
            raise


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis."""
    
    def __init__(self, app):
        super().__init__(app)
        self.rate_limit = 100  # requests per minute
        self.window = 60  # seconds
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply rate limiting to requests."""
        
        # Skip rate limiting for health checks
        if request.url.path.startswith("/health"):
            return await call_next(request)
        
        try:
            # Get client identifier
            client_ip = request.client.host if request.client else "unknown"
            user_id = getattr(request.state, 'user_id', None)
            
            # Use user ID if authenticated, otherwise use IP
            identifier = user_id if user_id else f"ip:{client_ip}"
            
            # Check rate limit
            key = f"cluster_manager:{identifier}"
            is_limited = await RateLimiter.is_rate_limited(key, self.rate_limit, self.window)
            
            if is_limited:
                # Rate limit exceeded
                rate_info = await RateLimiter.get_rate_limit_info(key)
                logger.warning(
                    f"Rate limit exceeded for {identifier}",
                    extra={
                        "identifier": identifier,
                        "count": rate_info["count"],
                        "limit": self.rate_limit
                    }
                )
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": f"Rate limit exceeded. Maximum {self.rate_limit} requests per minute."
                    }
                )
            
            # Add rate limit headers
            rate_info = await RateLimiter.get_rate_limit_info(key)
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(self.rate_limit)
            response.headers["X-RateLimit-Remaining"] = str(max(0, self.rate_limit - rate_info["count"]))
            response.headers["X-RateLimit-Reset"] = str(int(time.time()) + rate_info["ttl"])
            
            return response
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}", exc_info=True)
            # Continue without rate limiting if Redis is down
            return await call_next(request) 