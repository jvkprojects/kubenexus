"""
Middleware for KubeNexus Metrics Service.
Handles performance monitoring, caching, and metrics collection.
"""

import time
import json
import hashlib
from typing import Callable, Optional
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
    """Logging middleware for metrics service."""
    
    def __init__(self, app):
        super().__init__(app)
        self.logger = get_logger("metrics_middleware")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process requests with logging."""
        start_time = time.time()
        
        # Log incoming request
        self.logger.info(
            "Metrics request received",
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
            
            # Log response with metrics context
            self.logger.info(
                "Metrics request completed",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "status_code": response.status_code,
                    "process_time": round(process_time, 4),
                    "response_size": response.headers.get("content-length", "unknown"),
                    "cache_status": response.headers.get("X-Cache-Status", "none")
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
                "Metrics request failed",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "error": str(e),
                    "process_time": round(process_time, 4)
                },
                exc_info=True
            )
            
            raise


class MetricsCacheMiddleware(BaseHTTPMiddleware):
    """Caching middleware for metrics data."""
    
    def __init__(self, app):
        super().__init__(app)
        self.redis_client = get_redis_client()
        self.cache_ttl = getattr(settings, 'metrics_cache_ttl', 300)  # 5 minutes default
        self.logger = get_logger("metrics_cache")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle caching for GET requests to metrics endpoints."""
        
        # Only cache GET requests to metrics endpoints
        if request.method != "GET" or not self._should_cache(request.url.path):
            return await call_next(request)
        
        # Generate cache key
        cache_key = self._generate_cache_key(request)
        
        try:
            # Try to get from cache
            cached_response = await self.redis_client.get(cache_key)
            
            if cached_response:
                self.logger.debug(f"Cache hit for key: {cache_key}")
                response_data = json.loads(cached_response)
                
                response = Response(
                    content=response_data["content"],
                    status_code=response_data["status_code"],
                    headers=response_data["headers"]
                )
                response.headers["X-Cache-Status"] = "hit"
                return response
            
            # Cache miss - process request
            self.logger.debug(f"Cache miss for key: {cache_key}")
            response = await call_next(request)
            
            # Cache successful responses
            if response.status_code == 200:
                # Read response content
                content = b""
                async for chunk in response.body_iterator:
                    content += chunk
                
                # Prepare cache data
                cache_data = {
                    "content": content.decode(),
                    "status_code": response.status_code,
                    "headers": dict(response.headers)
                }
                
                # Store in cache
                await self.redis_client.setex(
                    cache_key,
                    self.cache_ttl,
                    json.dumps(cache_data)
                )
                
                # Create new response
                response = Response(
                    content=content,
                    status_code=response.status_code,
                    headers=response.headers
                )
                response.headers["X-Cache-Status"] = "miss"
            
            return response
            
        except Exception as e:
            self.logger.error(f"Cache error: {e}")
            # Continue without caching on Redis errors
            response = await call_next(request)
            response.headers["X-Cache-Status"] = "error"
            return response
    
    def _should_cache(self, path: str) -> bool:
        """Determine if the path should be cached."""
        cacheable_paths = [
            "/metrics",
            "/cluster",
            "/dashboard",
            "/performance"
        ]
        return any(cacheable_path in path for cacheable_path in cacheable_paths)
    
    def _generate_cache_key(self, request: Request) -> str:
        """Generate a cache key for the request."""
        # Include URL, query parameters, and relevant headers
        key_data = {
            "path": request.url.path,
            "query": str(request.url.query),
            "user_id": getattr(request.state, 'user_id', 'anonymous')
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return f"metrics_cache:{hashlib.md5(key_string.encode()).hexdigest()}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware for metrics service."""
    
    def __init__(self, app):
        super().__init__(app)
        self.redis_client = get_redis_client()
        self.rate_limit = getattr(settings, 'rate_limit_per_minute', 200)  # Higher limit for metrics
        self.logger = get_logger("metrics_rate_limit")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply rate limiting based on client IP."""
        
        # Skip rate limiting for health checks and internal requests
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        if client_ip == "unknown":
            return await call_next(request)
        
        # Create rate limit key
        rate_limit_key = f"metrics_rate_limit:{client_ip}"
        
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
                    "Rate limit exceeded for metrics service",
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


class MetricsCollectionMiddleware(BaseHTTPMiddleware):
    """Middleware to collect performance metrics about the service itself."""
    
    def __init__(self, app):
        super().__init__(app)
        self.logger = get_logger("metrics_collection")
        self.redis_client = get_redis_client()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Collect performance metrics for the metrics service."""
        
        start_time = time.time()
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate metrics
            process_time = time.time() - start_time
            
            # Store metrics in Redis for monitoring
            metrics_data = {
                "timestamp": time.time(),
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "process_time": process_time,
                "response_size": len(response.body) if hasattr(response, 'body') else 0
            }
            
            # Store recent metrics (last 1000 requests)
            try:
                await self.redis_client.lpush(
                    "metrics_service_performance",
                    json.dumps(metrics_data)
                )
                await self.redis_client.ltrim("metrics_service_performance", 0, 999)
                await self.redis_client.expire("metrics_service_performance", 3600)  # 1 hour
            except Exception as e:
                self.logger.debug(f"Failed to store performance metrics: {e}")
            
            # Log slow requests
            if process_time > 5.0:  # Log requests taking more than 5 seconds
                performance_logger.warning(
                    "Slow metrics request detected",
                    extra={
                        "method": request.method,
                        "path": request.url.path,
                        "process_time": process_time,
                        "status_code": response.status_code
                    }
                )
            
            return response
            
        except Exception as e:
            # Log failed requests
            process_time = time.time() - start_time
            
            self.logger.error(
                "Metrics service request failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "error": str(e),
                    "process_time": process_time
                }
            )
            
            raise


class CompressionMiddleware(BaseHTTPMiddleware):
    """Middleware to handle response compression for large metric datasets."""
    
    def __init__(self, app):
        super().__init__(app)
        self.min_size = 1024  # Compress responses larger than 1KB
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle response compression."""
        
        # Check if client accepts gzip
        accept_encoding = request.headers.get("accept-encoding", "")
        if "gzip" not in accept_encoding.lower():
            return await call_next(request)
        
        response = await call_next(request)
        
        # Only compress large responses
        content_length = response.headers.get("content-length")
        if content_length and int(content_length) < self.min_size:
            return response
        
        # Add compression hint for reverse proxy
        response.headers["X-Should-Compress"] = "true"
        
        return response


class HealthCheckMiddleware(BaseHTTPMiddleware):
    """Middleware for optimized health checks."""
    
    def __init__(self, app):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Optimize health check requests."""
        
        # Quick response for health checks
        if request.url.path == "/health":
            return Response(
                content='{"status": "healthy", "service": "metrics-service"}',
                media_type="application/json",
                status_code=200
            )
        
        return await call_next(request) 