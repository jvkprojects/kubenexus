"""
Rate Limiting Middleware for SRE Agent Service
"""

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared import get_logger, RateLimiter

logger = get_logger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware for SRE Agent Service."""
    
    async def dispatch(self, request: Request, call_next):
        """Process the request and apply rate limiting."""
        # Skip rate limiting for health and docs endpoints
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json", "/"]:
            response = await call_next(request)
            return response
        
        # Get client IP for rate limiting
        client_ip = request.client.host if request.client else "unknown"
        rate_limit_key = f"sre-agent:{client_ip}"
        
        try:
            # Check if client is rate limited
            is_limited = await RateLimiter.is_rate_limited(
                key=rate_limit_key,
                limit=60,  # 60 requests per minute
                window=60
            )
            
            if is_limited:
                logger.warning(f"Rate limit exceeded for {client_ip}")
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded",
                    headers={"Retry-After": "60"}
                )
            
            response = await call_next(request)
            
            # Add rate limit info to response headers
            rate_info = await RateLimiter.get_rate_limit_info(rate_limit_key)
            response.headers["X-RateLimit-Limit"] = "60"
            response.headers["X-RateLimit-Remaining"] = str(max(0, 60 - rate_info.get("count", 0)))
            response.headers["X-RateLimit-Reset"] = str(rate_info.get("reset_time", 0))
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Rate limit middleware error: {e}")
            # Don't block request if rate limiting fails
            response = await call_next(request)
            return response 