"""
Terminal router for KubeNexus Terminal Service.
Handles WebSocket-based kubectl terminal sessions.
"""

import asyncio
import json
import subprocess
import tempfile
import os
from typing import Dict, Any, Optional
from uuid import UUID, uuid4
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.responses import JSONResponse
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_logger,
    get_current_user,
    require_permission,
    audit_logger
)

router = APIRouter()
logger = get_logger(__name__)

# Active WebSocket connections
active_connections: Dict[str, WebSocket] = {}


class TerminalSession:
    def __init__(self, session_id: str, cluster_id: str, user_id: str, kubeconfig: str):
        self.session_id = session_id
        self.cluster_id = cluster_id
        self.user_id = user_id
        self.kubeconfig = kubeconfig
        self.process: Optional[subprocess.Popen] = None
        self.temp_kubeconfig_path: Optional[str] = None
        
    async def start_kubectl_session(self):
        """Start a kubectl session with the provided kubeconfig."""
        try:
            # Create temporary kubeconfig file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(self.kubeconfig)
                self.temp_kubeconfig_path = f.name
            
            # Start kubectl in interactive mode
            env = os.environ.copy()
            env['KUBECONFIG'] = self.temp_kubeconfig_path
            
            self.process = subprocess.Popen(
                ['kubectl', 'version'],  # Start with a simple command
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=0
            )
            
            logger.info(f"Started kubectl session for user {self.user_id} on cluster {self.cluster_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start kubectl session: {e}")
            return False
    
    async def execute_command(self, command: str) -> str:
        """Execute a kubectl command and return the output."""
        try:
            env = os.environ.copy()
            env['KUBECONFIG'] = self.temp_kubeconfig_path
            
            # Execute the command
            result = subprocess.run(
                command.split(),
                env=env,
                capture_output=True,
                text=True,
                timeout=30  # 30 second timeout
            )
            
            # Combine stdout and stderr
            output = result.stdout
            if result.stderr:
                output += f"\nError: {result.stderr}"
            
            # Log the command execution
            audit_logger.info(
                "Terminal command executed",
                extra={
                    "user_id": self.user_id,
                    "cluster_id": self.cluster_id,
                    "command": command,
                    "return_code": result.returncode
                }
            )
            
            return output
            
        except subprocess.TimeoutExpired:
            return "Error: Command timed out after 30 seconds"
        except Exception as e:
            logger.error(f"Failed to execute command: {e}")
            return f"Error: {str(e)}"
    
    def cleanup(self):
        """Clean up the terminal session."""
        try:
            if self.process:
                self.process.terminate()
                self.process = None
            
            if self.temp_kubeconfig_path and os.path.exists(self.temp_kubeconfig_path):
                os.unlink(self.temp_kubeconfig_path)
                self.temp_kubeconfig_path = None
                
            logger.info(f"Cleaned up terminal session {self.session_id}")
            
        except Exception as e:
            logger.error(f"Failed to cleanup session: {e}")


# Active terminal sessions
active_sessions: Dict[str, TerminalSession] = {}


@router.websocket("/ws/{cluster_id}")
async def websocket_terminal(
    websocket: WebSocket,
    cluster_id: UUID
):
    """WebSocket endpoint for terminal sessions."""
    
    await websocket.accept()
    session_id = str(uuid4())
    
    try:
        # Get user information from WebSocket headers/query params
        # In a real implementation, you'd extract this from JWT token in the WebSocket connection
        user_info = {"id": "anonymous", "username": "anonymous"}  # Placeholder
        
        # Store the WebSocket connection
        active_connections[session_id] = websocket
        
        # Send welcome message
        await websocket.send_text(json.dumps({
            "type": "welcome",
            "message": f"Connected to KubeNexus Terminal for cluster {cluster_id}",
            "session_id": session_id
        }))
        
        # Wait for authentication and kubeconfig
        auth_message = await websocket.receive_text()
        auth_data = json.loads(auth_message)
        
        if auth_data.get("type") != "auth":
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": "Authentication required"
            }))
            return
        
        # In a real implementation, validate the JWT token here
        kubeconfig = auth_data.get("kubeconfig", "")
        if not kubeconfig:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": "Kubeconfig required"
            }))
            return
        
        # Create terminal session
        session = TerminalSession(session_id, str(cluster_id), user_info["id"], kubeconfig)
        active_sessions[session_id] = session
        
        # Initialize kubectl session
        if not await session.start_kubectl_session():
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": "Failed to initialize kubectl session"
            }))
            return
        
        await websocket.send_text(json.dumps({
            "type": "ready",
            "message": "Terminal session ready. Type 'help' for available commands."
        }))
        
        # Handle incoming commands
        while True:
            try:
                message = await websocket.receive_text()
                data = json.loads(message)
                
                if data.get("type") == "command":
                    command = data.get("command", "").strip()
                    
                    if not command:
                        continue
                    
                    # Handle special commands
                    if command == "help":
                        help_text = """
Available commands:
- kubectl <command>: Execute kubectl commands
- clear: Clear the terminal
- exit: Close the terminal session

Examples:
- kubectl get pods
- kubectl get nodes
- kubectl describe pod <pod-name>
- kubectl logs <pod-name>
"""
                        await websocket.send_text(json.dumps({
                            "type": "output",
                            "data": help_text
                        }))
                        continue
                    
                    elif command == "clear":
                        await websocket.send_text(json.dumps({
                            "type": "clear"
                        }))
                        continue
                    
                    elif command == "exit":
                        await websocket.send_text(json.dumps({
                            "type": "message",
                            "data": "Session ended."
                        }))
                        break
                    
                    # Execute kubectl command
                    if command.startswith("kubectl "):
                        output = await session.execute_command(command)
                        await websocket.send_text(json.dumps({
                            "type": "output",
                            "data": output
                        }))
                    else:
                        await websocket.send_text(json.dumps({
                            "type": "output",
                            "data": f"Unknown command: {command}. Type 'help' for available commands."
                        }))
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"Error handling WebSocket message: {e}")
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": f"Error: {str(e)}"
                }))
    
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session {session_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        # Cleanup
        if session_id in active_connections:
            del active_connections[session_id]
        if session_id in active_sessions:
            active_sessions[session_id].cleanup()
            del active_sessions[session_id]


@router.get("/sessions")
async def list_active_sessions(
    current_user: Dict[str, Any] = Depends(get_current_user),
    _: None = Depends(require_permission("terminal.sessions.list"))
):
    """List active terminal sessions."""
    
    try:
        sessions = []
        for session_id, session in active_sessions.items():
            sessions.append({
                "session_id": session_id,
                "cluster_id": session.cluster_id,
                "user_id": session.user_id,
                "created_at": "2024-01-01T00:00:00Z"  # Would be stored in real implementation
            })
        
        return {
            "sessions": sessions,
            "total_count": len(sessions)
        }
        
    except Exception as e:
        logger.error(f"Failed to list sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list sessions: {str(e)}"
        )


@router.delete("/sessions/{session_id}")
async def terminate_session(
    session_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _: None = Depends(require_permission("terminal.sessions.terminate"))
):
    """Terminate a terminal session."""
    
    try:
        if session_id not in active_sessions:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        
        # Cleanup the session
        active_sessions[session_id].cleanup()
        del active_sessions[session_id]
        
        # Close WebSocket if still connected
        if session_id in active_connections:
            await active_connections[session_id].close()
            del active_connections[session_id]
        
        audit_logger.info(
            "Terminal session terminated",
            extra={
                "user_id": current_user["id"],
                "session_id": session_id
            }
        )
        
        return {"message": "Session terminated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to terminate session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to terminate session: {str(e)}"
        )


@router.get("/health")
async def terminal_health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "active_sessions": len(active_sessions),
        "active_connections": len(active_connections)
    } 