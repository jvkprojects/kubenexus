"""
Middleware for KubeNexus API Gateway.
Handles authentication, RBAC, logging, rate limiting, and service proxying.
"""

import time
import json
from typing import Callable, Dict, Any, Optional
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse, JSONResponse
import httpx
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_logger,
    get_settings,
    AuthenticationError,
    AuthorizationError
)

logger = get_logger(__name__)
settings = get_settings()


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Authentication middleware for validating JWT tokens."""
    
    def __init__(self, app):
        super().__init__(app)
        self.excluded_paths = [
            "/health", "/docs", "/redoc", "/openapi.json", "/", "/services",
            # Auth endpoints that don't require authentication
            "/api/auth/login", "/api/v1/auth/login",
            "/api/auth/register", "/api/v1/auth/register",
            "/api/auth/forgot-password", "/api/v1/auth/forgot-password",
            "/api/auth/reset-password", "/api/v1/auth/reset-password",
            "/api/auth/sso", "/api/v1/auth/sso",
            "/api/auth/ldap-login", "/api/v1/auth/ldap-login"
        ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process authentication for incoming requests."""
        
        # Skip authentication for excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)
        
        try:
            # Get authorization header
            authorization = request.headers.get("authorization")
            if not authorization or not authorization.startswith("Bearer "):
                raise AuthenticationError("Missing or invalid authorization header")
            
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
                        raise AuthenticationError("Invalid token")
                    
                    user_data = response.json()
                    
                    # Add user context to request state
                    request.state.current_user = user_data
                    request.state.user_id = user_data["id"]
                    request.state.username = user_data["username"]
                    request.state.user_permissions = user_data.get("permissions", [])
                    
                except httpx.RequestError:
                    logger.error("Failed to verify token with auth service")
                    raise AuthenticationError("Authentication service unavailable")
            
            return await call_next(request)
            
        except AuthenticationError:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Authentication required"}
            )
        except Exception as e:
            logger.error(f"Authentication middleware error: {e}", exc_info=True)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Authentication error"}
            )


class RBACMiddleware(BaseHTTPMiddleware):
    """Role-Based Access Control middleware."""
    
    def __init__(self, app):
        super().__init__(app)
        self.endpoint_permissions = {
            # Cluster management permissions
            "/api/v1/clusters": {
                "GET": "cluster:read",
                "POST": "cluster:create"
            },
            "/api/v1/clusters/*": {
                "GET": "cluster:read",
                "PUT": "cluster:update",
                "DELETE": "cluster:delete"
            },
            # Cloud provider permissions
            "/api/v1/cloud-providers": {
                "GET": "cloud_provider:read",
                "POST": "cloud_provider:create"
            },
            "/api/v1/cloud-providers/*": {
                "GET": "cloud_provider:read",
                "PUT": "cloud_provider:update",
                "DELETE": "cloud_provider:delete"
            },
            # User management permissions
            "/api/v1/users": {
                "GET": "user:read",
                "POST": "user:create"
            },
            "/api/v1/users/*": {
                "GET": "user:read",
                "PUT": "user:update",
                "DELETE": "user:delete"
            }
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Enforce RBAC for incoming requests."""
        
        # Skip RBAC for excluded paths
        if not hasattr(request.state, 'current_user'):
            return await call_next(request)
        
        # Check if endpoint requires specific permission
        required_permission = self._get_required_permission(request.url.path, request.method)
        
        if required_permission:
            user_permissions = getattr(request.state, 'user_permissions', [])
            
            if required_permission not in user_permissions:
                logger.warning(
                    f"Access denied for user {request.state.username} to {request.url.path}",
                    extra={
                        "user_id": request.state.user_id,
                        "required_permission": required_permission,
                        "user_permissions": user_permissions
                    }
                )
                raise AuthorizationError(f"Permission denied: {required_permission}")
        
        return await call_next(request)
    
    def _get_required_permission(self, path: str, method: str) -> Optional[str]:
        """Get required permission for endpoint."""
        
        # Check exact match first
        if path in self.endpoint_permissions:
            return self.endpoint_permissions[path].get(method)
        
        # Check wildcard matches
        for pattern, permissions in self.endpoint_permissions.items():
            if pattern.endswith("*"):
                prefix = pattern[:-1]
                if path.startswith(prefix):
                    return permissions.get(method)
        
        return None


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging HTTP requests and responses."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request and response details."""
        
        start_time = time.time()
        
        # Log request
        user_id = getattr(request.state, 'user_id', 'anonymous')
        client_ip = request.client.host if request.client else "unknown"
        
        logger.info(
            "Gateway request started",
            extra={
                "method": request.method,
                "url": str(request.url),
                "user_id": user_id,
                "client_ip": client_ip,
                "user_agent": request.headers.get("user-agent", "")
            }
        )
        
        # Process request
        try:
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Log response
            logger.info(
                "Gateway request completed",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "status_code": response.status_code,
                    "duration": duration,
                    "user_id": user_id,
                    "client_ip": client_ip
                }
            )
            
            # Log performance metrics
            # performance_logger.log_request_metrics(
            #     service="api-gateway",
            #     endpoint=request.url.path,
            #     method=request.method,
            #     status_code=response.status_code,
            #     duration=duration,
            #     user_id=user_id
            # )
            
            # Add response headers
            response.headers["X-Request-ID"] = getattr(request.state, 'request_id', 'unknown')
            response.headers["X-Gateway-Duration"] = str(duration)
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "Gateway request failed",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "duration": duration,
                    "user_id": user_id,
                    "client_ip": client_ip,
                    "error": str(e)
                },
                exc_info=True
            )
            raise


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis."""
    
    def __init__(self, app):
        super().__init__(app)
        self.default_rate_limit = 1000  # requests per minute
        self.window = 60  # seconds
        
        # Different rate limits for different endpoints
        self.endpoint_limits = {
            "/api/v1/auth": 20,  # Auth endpoints are more sensitive
            "/api/v1/clusters": 100,
            "/api/v1/users": 50
        }
    
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
            
            # Get rate limit for this endpoint
            rate_limit = self._get_rate_limit(request.url.path)
            
            # For now, skip Redis-based rate limiting since Redis client is not available
            # This can be enhanced later when Redis integration is properly configured
            # TODO: Implement Redis-based rate limiting when Redis client is available
            
            # Process request without rate limiting for now
            response = await call_next(request)
            
            # Add rate limit headers (informational)
            response.headers["X-RateLimit-Limit"] = str(rate_limit)
            response.headers["X-RateLimit-Remaining"] = str(rate_limit - 1)  # Placeholder
            response.headers["X-RateLimit-Reset"] = str(int(time.time()) + self.window)
            
            return response
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}", exc_info=True)
            # Continue without rate limiting if Redis is down
            return await call_next(request)
    
    def _get_rate_limit(self, path: str) -> int:
        """Get rate limit for a specific path."""
        
        for endpoint, limit in self.endpoint_limits.items():
            if path.startswith(endpoint):
                return limit
        
        return self.default_rate_limit


class ProxyMiddleware(BaseHTTPMiddleware):
    """Middleware for proxying requests to backend services."""
    
    def __init__(self, app):
        super().__init__(app)
        self.service_routes = {
            # Legacy v1 routes
            "/api/v1/auth": settings.auth_service_url,
            "/api/v1/users": settings.auth_service_url,
            "/api/v1/clusters": settings.cluster_manager_service_url,
            "/api/v1/cloud-providers": settings.cluster_manager_service_url,
            "/api/v1/kubeconfig": settings.cluster_manager_service_url,
            "/api/v1/sre": settings.sre_agent_service_url,
            "/api/v1/audit": settings.audit_log_service_url,
            "/api/v1/metrics": settings.metrics_service_url,
            "/api/v1/terminal": settings.terminal_service_url,
            # Frontend-compatible routes (without v1)
            "/api/auth": settings.auth_service_url,
            "/api/users": settings.auth_service_url,
            "/api/clusters": settings.cluster_manager_service_url,
            "/api/cloud-providers": settings.cluster_manager_service_url,
            "/api/kubeconfig": settings.cluster_manager_service_url,
            "/api/sre": settings.sre_agent_service_url,
            "/api/audit": settings.audit_log_service_url,
            "/api/metrics": settings.metrics_service_url,
            "/api/terminal": settings.terminal_service_url
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Proxy requests to appropriate backend services."""
        
        # Check if this is a proxy request
        service_url = self._get_service_url(request.url.path)
        
        if not service_url:
            # Not a proxy request, continue normally
            return await call_next(request)
        
        try:
            # Build target URL
            path_without_prefix = self._strip_api_prefix(request.url.path)
            target_url = f"{service_url}{path_without_prefix}"
            
            # Add query parameters
            if request.url.query:
                target_url += f"?{request.url.query}"
            
            # Get request body if present
            body = None
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
            
            # Forward headers (excluding host)
            headers = dict(request.headers)
            headers.pop("host", None)
            
            # Make request to backend service
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    content=body,
                    follow_redirects=False
                )
            
            # Forward response
            response_headers = dict(response.headers)
            response_headers.pop("content-length", None)  # Let FastAPI handle this
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get("content-type")
            )
            
        except httpx.RequestError as e:
            logger.error(f"Proxy request failed: {e}", exc_info=True)
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": f"Backend service unavailable: {str(e)}"}
            )
        except Exception as e:
            logger.error(f"Proxy error: {e}", exc_info=True)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Proxy error"}
            )
    
    def _get_service_url(self, path: str) -> Optional[str]:
        """Get backend service URL for a given path."""
        
        for route_prefix, service_url in self.service_routes.items():
            if path.startswith(route_prefix):
                return service_url
        
        return None
    
    def _strip_api_prefix(self, path: str) -> str:
        """Strip /api/v1 or /api prefix and map to service-specific paths."""
        
        # Remove /api/v1 prefix
        if path.startswith("/api/v1"):
            path = path[7:]  # Remove "/api/v1"
        # Remove /api prefix for frontend routes
        elif path.startswith("/api"):
            path = path[4:]  # Remove "/api"
        
        # Map to service-specific paths
        if path.startswith("/auth") or path.startswith("/users"):
            return path
        elif path.startswith("/clusters") or path.startswith("/cloud-providers") or path.startswith("/kubeconfig"):
            return path
        elif path.startswith("/sre"):
            return path
        elif path.startswith("/audit"):
            return path
        elif path.startswith("/metrics"):
            return path
        elif path.startswith("/terminal"):
            return path
        
        return path 