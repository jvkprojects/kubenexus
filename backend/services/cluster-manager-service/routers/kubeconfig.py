"""
Kubeconfig router for KubeNexus Cluster Manager Service.
Handles kubeconfig file management and downloads.
"""

from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
import yaml
import base64
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    KubernetesCluster,
    kubeconfig_manager,
    audit_logger,
    require_permission,
    get_current_user
)

router = APIRouter()
logger = get_logger(__name__)


class KubeconfigResponse(BaseModel):
    cluster_id: str
    cluster_name: str
    kubeconfig: str
    generated_at: datetime


@router.get("/{cluster_id}/download")
async def download_kubeconfig(
    cluster_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cluster:read"))
):
    """Download kubeconfig file for a cluster."""
    
    try:
        # Get cluster
        result = await db.execute(
            select(KubernetesCluster).where(KubernetesCluster.id == cluster_id)
        )
        cluster = result.scalar_one_or_none()
        
        if not cluster:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cluster not found"
            )
        
        if not cluster.kubeconfig:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Kubeconfig not available for this cluster"
            )
        
        # Decrypt kubeconfig
        kubeconfig_content = kubeconfig_manager.decrypt_kubeconfig(cluster.kubeconfig)
        
        # Log access
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="download_kubeconfig",
            resource_type="cluster",
            resource_id=str(cluster.id),
            resource_name=cluster.name,
            success=True
        )
        
        # Return as downloadable file
        response = Response(
            content=kubeconfig_content,
            media_type="application/x-yaml",
            headers={
                "Content-Disposition": f"attachment; filename={cluster.name}-kubeconfig.yaml"
            }
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to download kubeconfig for {cluster_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to download kubeconfig"
        )


@router.get("/{cluster_id}", response_model=KubeconfigResponse)
async def get_kubeconfig(
    cluster_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cluster:read"))
):
    """Get kubeconfig content for a cluster."""
    
    try:
        # Get cluster
        result = await db.execute(
            select(KubernetesCluster).where(KubernetesCluster.id == cluster_id)
        )
        cluster = result.scalar_one_or_none()
        
        if not cluster:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cluster not found"
            )
        
        if not cluster.kubeconfig:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Kubeconfig not available for this cluster"
            )
        
        # Decrypt kubeconfig
        kubeconfig_content = kubeconfig_manager.decrypt_kubeconfig(cluster.kubeconfig)
        
        # Log access
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="get_kubeconfig",
            resource_type="cluster",
            resource_id=str(cluster.id),
            resource_name=cluster.name,
            success=True
        )
        
        return KubeconfigResponse(
            cluster_id=cluster_id,
            cluster_name=cluster.name,
            kubeconfig=kubeconfig_content,
            generated_at=datetime.now(timezone.utc)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get kubeconfig for {cluster_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get kubeconfig"
        ) 