"""
Middleware for KubeNexus Terminal Service.
Handles WebSocket connections, security, and session management.
"""

import time
import json
from typing import Callable
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.websockets import WebSocket
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_logger,
    get_settings,
    audit_logger
)

logger = get_logger(__name__)
settings = get_settings()


class LoggingMiddleware(BaseHTTPMiddleware):
    """Logging middleware for terminal service."""
    
    def __init__(self, app):
        super().__init__(app)
        self.logger = get_logger("terminal_middleware")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process requests with logging."""
        start_time = time.time()
        
        # Log incoming request (excluding WebSocket upgrades for cleaner logs)
        if not self._is_websocket_request(request):
            self.logger.info(
                "Terminal request received",
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
            
            # Log response (excluding WebSocket connections)
            if not self._is_websocket_request(request):
                self.logger.info(
                    "Terminal request completed",
                    extra={
                        "method": request.method,
                        "url": str(request.url),
                        "status_code": response.status_code,
                        "process_time": round(process_time, 4),
                        "response_size": response.headers.get("content-length", "unknown")
                    }
                )
            
            # Add processing time header
            if hasattr(response, 'headers'):
                response.headers["X-Process-Time"] = str(round(process_time, 4))
            
            return response
            
        except Exception as e:
            # Calculate processing time for errors
            process_time = time.time() - start_time
            
            # Log error
            self.logger.error(
                "Terminal request failed",
                extra={
                    "method": request.method,
                    "url": str(request.url),
                    "error": str(e),
                    "process_time": round(process_time, 4)
                },
                exc_info=True
            )
            
            raise
    
    def _is_websocket_request(self, request: Request) -> bool:
        """Check if request is a WebSocket upgrade."""
        return (
            request.headers.get("upgrade", "").lower() == "websocket" or
            request.url.path.startswith("/ws/")
        )


class WebSocketSecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for WebSocket connections."""
    
    def __init__(self, app):
        super().__init__(app)
        self.logger = get_logger("terminal_websocket_security")
        # self.redis_client = get_redis_client() # This line was removed as per the new_code
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply security checks for WebSocket connections."""
        
        # Only apply to WebSocket endpoints
        if not request.url.path.startswith("/ws/"):
            return await call_next(request)
        
        try:
            # Validate WebSocket upgrade headers
            if not self._validate_websocket_headers(request):
                self.logger.warning(
                    "Invalid WebSocket headers",
                    extra={
                        "url": str(request.url),
                        "client_ip": request.client.host if request.client else "unknown",
                        "headers": dict(request.headers)
                    }
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid WebSocket request"
                )
            
            # Check rate limiting for WebSocket connections
            client_ip = request.client.host if request.client else "unknown"
            # if not await self._check_websocket_rate_limit(client_ip): # This line was removed as per the new_code
            #     self.logger.warning(
            #         "WebSocket rate limit exceeded",
            #         extra={
            #             "client_ip": client_ip,
            #             "url": str(request.url)
            #         }
            #     )
            #     raise HTTPException(
            #         status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            #         detail="Too many WebSocket connections from this IP"
            #     )
            
            # Log WebSocket connection attempt
            audit_logger.info(
                "WebSocket connection attempted",
                extra={
                    "client_ip": client_ip,
                    "url": str(request.url),
                    "user_agent": request.headers.get("user-agent", "unknown")
                }
            )
            
            return await call_next(request)
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"WebSocket security check failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="WebSocket security validation failed"
            )
    
    def _validate_websocket_headers(self, request: Request) -> bool:
        """Validate WebSocket upgrade headers."""
        required_headers = {
            "upgrade": "websocket",
            "connection": "upgrade"
        }
        
        for header, expected_value in required_headers.items():
            actual_value = request.headers.get(header, "").lower()
            if expected_value not in actual_value:
                return False
        
        # Check for WebSocket version
        ws_version = request.headers.get("sec-websocket-version")
        if not ws_version or ws_version not in ["13"]:
            return False
        
        return True
    
    # async def _check_websocket_rate_limit(self, client_ip: str) -> bool: # This line was removed as per the new_code
    #     """Check WebSocket connection rate limit.""" # This line was removed as per the new_code
    #     if client_ip == "unknown": # This line was removed as per the new_code
    #         return True # This line was removed as per the new_code
        
    #     rate_limit_key = f"terminal_ws_rate_limit:{client_ip}" # This line was removed as per the new_code
    #     max_connections = 10  # Max 10 concurrent WebSocket connections per IP # This line was removed as per the new_code
        
    #     try: # This line was removed as per the new_code
    #         current_connections = await self.redis_client.get(rate_limit_key) # This line was removed as per the new_code
            
    #         if current_connections is None: # This line was removed as per the new_code
    #             # First connection from this IP # This line was removed as per the new_code
    #             await self.redis_client.setex(rate_limit_key, 3600, 1)  # 1 hour expiry # This line was removed as per the new_code
    #             return True # This line was removed as per the new_code
            
    #         if int(current_connections) >= max_connections: # This line was removed as per the new_code
    #             return False # This line was removed as per the new_code
            
    #         # Increment connection count # This line was removed as per the new_code
    #         await self.redis_client.incr(rate_limit_key) # This line was removed as per the new_code
    #         return True # This line was removed as per the new_code
            
    #     except Exception as e: # This line was removed as per the new_code
    #         self.logger.error(f"WebSocket rate limit check failed: {e}") # This line was removed as per the new_code
    #         # Allow connection on Redis errors # This line was removed as per the new_code
    #         return True # This line was removed as per the new_code


class SessionTrackingMiddleware(BaseHTTPMiddleware):
    """Middleware to track terminal sessions."""
    
    def __init__(self, app):
        super().__init__(app)
        self.logger = get_logger("terminal_session_tracking")
        # self.redis_client = get_redis_client() # This line was removed as per the new_code
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Track terminal session operations."""
        
        # Only track session-related endpoints
        if not any(path in request.url.path for path in ["/sessions", "/ws/"]):
            return await call_next(request)
        
        start_time = time.time()
        
        try:
            # Extract user information if available
            user_id = getattr(request.state, 'user_id', 'anonymous')
            
            # Process request
            response = await call_next(request)
            
            # Log session operation
            if request.url.path.startswith("/sessions"):
                audit_logger.info(
                    "Terminal session operation",
                    extra={
                        "user_id": user_id,
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": response.status_code,
                        "duration": round(time.time() - start_time, 4),
                        "client_ip": request.client.host if request.client else "unknown"
                    }
                )
            
            # Update session metrics
            if request.method in ["POST", "DELETE"] and "/sessions" in request.url.path:
                await self._update_session_metrics(request.method, user_id)
            
            return response
            
        except Exception as e:
            # Log failed session operation
            audit_logger.error(
                "Terminal session operation failed",
                extra={
                    "user_id": getattr(request.state, 'user_id', 'anonymous'),
                    "method": request.method,
                    "path": request.url.path,
                    "error": str(e),
                    "duration": round(time.time() - start_time, 4)
                }
            )
            raise
    
    async def _update_session_metrics(self, method: str, user_id: str):
        """Update session metrics in Redis."""
        try:
            if method == "POST":
                # Session created
                # await self.redis_client.incr("terminal_sessions_created") # This line was removed as per the new_code
                # await self.redis_client.incr(f"terminal_sessions_user:{user_id}") # This line was removed as per the new_code
                pass # This line was removed as per the new_code
            elif method == "DELETE":
                # Session terminated
                # await self.redis_client.incr("terminal_sessions_terminated") # This line was removed as per the new_code
                # user_sessions = await self.redis_client.get(f"terminal_sessions_user:{user_id}") # This line was removed as per the new_code
                # if user_sessions and int(user_sessions) > 0: # This line was removed as per the new_code
                #     await self.redis_client.decr(f"terminal_sessions_user:{user_id}") # This line was removed as per the new_code
                pass # This line was removed as per the new_code
        except Exception as e:
            self.logger.debug(f"Failed to update session metrics: {e}")


class CommandAuditMiddleware(BaseHTTPMiddleware):
    """Middleware for auditing terminal commands (for non-WebSocket endpoints)."""
    
    def __init__(self, app):
        super().__init__(app)
        self.logger = get_logger("terminal_command_audit")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Audit terminal commands for compliance."""
        
        # Skip non-terminal endpoints
        if not request.url.path.startswith("/terminal"):
            return await call_next(request)
        
        try:
            # Extract user information
            user_id = getattr(request.state, 'user_id', 'anonymous')
            
            # Log terminal access
            audit_logger.info(
                "Terminal access attempted",
                extra={
                    "user_id": user_id,
                    "method": request.method,
                    "path": request.url.path,
                    "client_ip": request.client.host if request.client else "unknown",
                    "user_agent": request.headers.get("user-agent", "unknown")
                }
            )
            
            return await call_next(request)
            
        except Exception as e:
            self.logger.error(f"Command audit failed: {e}")
            raise


class HealthCheckMiddleware(BaseHTTPMiddleware):
    """Middleware for optimized health checks."""
    
    def __init__(self, app):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Optimize health check requests."""
        
        # Quick response for health checks
        if request.url.path == "/health":
            return Response(
                content='{"status": "healthy", "service": "terminal-service"}',
                media_type="application/json",
                status_code=200
            )
        
        return await call_next(request)


class CORSMiddleware(BaseHTTPMiddleware):
    """CORS middleware specifically for WebSocket connections."""
    
    def __init__(self, app):
        super().__init__(app)
        self.allowed_origins = getattr(settings, 'backend_cors_origins', ['*'])
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle CORS for WebSocket and regular requests."""
        
        # Handle preflight requests
        if request.method == "OPTIONS":
            return Response(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age": "86400"
                }
            )
        
        response = await call_next(request)
        
        # Add CORS headers to response
        if hasattr(response, 'headers'):
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Credentials"] = "true"
        
        return response 