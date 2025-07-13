"""
Middleware for KubeNexus Authentication Service.
"""

import time
import uuid
from typing import Callable
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import get_logger, RateLimiter, get_settings

logger = get_logger(__name__)
settings = get_settings()


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log details."""
        
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Get client info
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        
        # Start timer
        start_time = time.time()
        
        # Log request
        logger.info(
            "Request started",
            request_id=request_id,
            method=request.method,
            url=str(request.url),
            client_ip=client_ip,
            user_agent=user_agent
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Log response
            logger.info(
                "Request completed",
                request_id=request_id,
                status_code=response.status_code,
                duration_ms=round(duration * 1000, 2)
            )
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as e:
            # Calculate duration
            duration = time.time() - start_time
            
            # Log error
            logger.error(
                "Request failed",
                request_id=request_id,
                error=str(e),
                duration_ms=round(duration * 1000, 2),
                exc_info=True
            )
            
            # Re-raise exception
            raise
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check for forwarded headers (when behind proxy/load balancer)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        # Fall back to direct connection
        if hasattr(request.client, 'host'):
            return request.client.host
        
        return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware for rate limiting requests."""
    
    def __init__(self, app, calls_per_minute: int = None, burst_limit: int = None):
        super().__init__(app)
        self.calls_per_minute = calls_per_minute or settings.rate_limit_per_minute
        self.burst_limit = burst_limit or settings.rate_limit_burst
        self.rate_limiter = RateLimiter()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with rate limiting."""
        
        # Get client identifier
        client_id = self._get_client_identifier(request)
        
        # Check rate limit
        is_limited = await self.rate_limiter.is_rate_limited(
            key=client_id,
            limit=self.calls_per_minute,
            window=60  # 1 minute
        )
        
        if is_limited:
            # Get rate limit info
            rate_info = await self.rate_limiter.get_rate_limit_info(client_id)
            
            logger.warning(
                "Rate limit exceeded",
                client_id=client_id,
                count=rate_info["count"],
                ttl=rate_info["ttl"]
            )
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": rate_info["ttl"]
                },
                headers={
                    "Retry-After": str(rate_info["ttl"]),
                    "X-RateLimit-Limit": str(self.calls_per_minute),
                    "X-RateLimit-Remaining": str(max(0, self.calls_per_minute - rate_info["count"])),
                    "X-RateLimit-Reset": str(rate_info["ttl"])
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        rate_info = await self.rate_limiter.get_rate_limit_info(client_id)
        response.headers["X-RateLimit-Limit"] = str(self.calls_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self.calls_per_minute - rate_info["count"]))
        
        return response
    
    def _get_client_identifier(self, request: Request) -> str:
        """Get client identifier for rate limiting."""
        # Check for authenticated user
        authorization = request.headers.get("authorization")
        if authorization:
            # Extract user from token if possible
            try:
                from shared import TokenManager
                token = authorization.replace("Bearer ", "")
                user_id = TokenManager.extract_user_id(token)
                if user_id:
                    return f"user:{user_id}"
            except:
                pass
        
        # Fall back to IP address
        client_ip = self._get_client_ip(request)
        return f"ip:{client_ip}"
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        if hasattr(request.client, 'host'):
            return request.client.host
        
        return "unknown"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware for adding security headers."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers to response."""
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Add HSTS header for HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Add CSP header for API responses
        if request.url.path.startswith("/docs") or request.url.path.startswith("/redoc"):
            # Allow inline scripts for API documentation
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'"
            )
        else:
            # Strict CSP for API endpoints
            response.headers["Content-Security-Policy"] = "default-src 'none'"
        
        return response


class AuthContextMiddleware(BaseHTTPMiddleware):
    """Middleware for adding authentication context to requests."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add authentication context to request state."""
        
        # Initialize auth context
        request.state.user_id = None
        request.state.username = None
        request.state.is_authenticated = False
        
        # Check for authentication token
        authorization = request.headers.get("authorization")
        if authorization and authorization.startswith("Bearer "):
            try:
                from shared import TokenManager, get_async_db
                
                token = authorization.replace("Bearer ", "")
                
                # Verify token
                payload = TokenManager.verify_token(token)
                if payload and payload.get("type") == "access":
                    # Check if token is blacklisted
                    is_blacklisted = await TokenManager.is_token_blacklisted(token)
                    if not is_blacklisted:
                        # Add user context
                        request.state.user_id = payload.get("sub")
                        request.state.username = payload.get("username")
                        request.state.is_authenticated = True
                        
                        # Log authenticated request
                        logger.debug(
                            "Authenticated request",
                            user_id=request.state.user_id,
                            username=request.state.username
                        )
            except Exception as e:
                logger.debug(f"Token verification failed: {e}")
        
        # Process request
        response = await call_next(request)
        return response


class CORSPreflightMiddleware(BaseHTTPMiddleware):
    """Middleware for handling CORS preflight requests."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle CORS preflight requests."""
        
        if request.method == "OPTIONS":
            # Handle preflight request
            response = Response()
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = (
                "Authorization, Content-Type, Accept, Origin, User-Agent, "
                "X-Requested-With, X-Request-ID"
            )
            response.headers["Access-Control-Max-Age"] = "86400"  # 24 hours
            return response
        
        # Process normal request
        response = await call_next(request)
        return response 