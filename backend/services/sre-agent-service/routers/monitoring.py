"""
Monitoring router for KubeNexus SRE Agent Service.
Handles cluster monitoring, metrics collection, and health checks.
"""

from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    KubernetesCluster,
    require_permission,
    get_current_user
)

router = APIRouter()
logger = get_logger(__name__)


class ClusterMetrics(BaseModel):
    cluster_id: str
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_io: float
    pod_count: int
    node_count: int
    namespace_count: int


class MonitoringOverview(BaseModel):
    total_clusters: int
    healthy_clusters: int
    unhealthy_clusters: int
    total_nodes: int
    total_pods: int
    avg_cpu_usage: float
    avg_memory_usage: float
    alerts_count: int


@router.get("/overview", response_model=MonitoringOverview)
async def get_monitoring_overview(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cluster:read"))
):
    """Get monitoring overview across all clusters."""
    
    try:
        # Get all clusters
        result = await db.execute(select(KubernetesCluster))
        clusters = result.scalars().all()
        
        # Mock metrics calculation
        total_clusters = len(clusters)
        healthy_clusters = sum(1 for c in clusters if c.status == 'active')
        unhealthy_clusters = total_clusters - healthy_clusters
        
        # Mock aggregated metrics
        total_nodes = sum(c.node_count or 0 for c in clusters)
        total_pods = total_nodes * 10  # Mock calculation
        avg_cpu_usage = 65.5  # Mock
        avg_memory_usage = 72.3  # Mock
        alerts_count = 3  # Mock
        
        return MonitoringOverview(
            total_clusters=total_clusters,
            healthy_clusters=healthy_clusters,
            unhealthy_clusters=unhealthy_clusters,
            total_nodes=total_nodes,
            total_pods=total_pods,
            avg_cpu_usage=avg_cpu_usage,
            avg_memory_usage=avg_memory_usage,
            alerts_count=alerts_count
        )
        
    except Exception as e:
        logger.error(f"Failed to get monitoring overview: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get monitoring overview"
        )


@router.get("/clusters/{cluster_id}/metrics", response_model=ClusterMetrics)
async def get_cluster_metrics(
    cluster_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cluster:read"))
):
    """Get current metrics for a specific cluster."""
    
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
        
        # Mock metrics collection
        metrics = ClusterMetrics(
            cluster_id=cluster_id,
            timestamp=datetime.now(timezone.utc),
            cpu_usage=68.5,
            memory_usage=74.2,
            disk_usage=45.8,
            network_io=1024.5,
            pod_count=42,
            node_count=cluster.node_count or 3,
            namespace_count=8
        )
        
        return metrics
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get cluster metrics for {cluster_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get cluster metrics"
        ) 