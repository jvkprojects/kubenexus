"""
Metrics router for KubeNexus Metrics Service.
Handles collection and exposure of system metrics and performance data.
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc
from pydantic import BaseModel, Field
import asyncio
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    get_settings,
    MetricsCache,
    KubernetesCluster,
    get_current_user,
    require_permission
)

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()


# Pydantic models
class MetricDataPoint(BaseModel):
    """Individual metric data point."""
    timestamp: datetime
    value: float
    labels: Optional[Dict[str, str]] = {}


class SystemMetrics(BaseModel):
    """System-level metrics."""
    cpu_usage_percent: float
    memory_usage_percent: float
    disk_usage_percent: float
    network_in_bytes: int
    network_out_bytes: int
    timestamp: datetime


class ClusterMetrics(BaseModel):
    """Cluster-level metrics."""
    cluster_id: str
    cluster_name: str
    nodes_total: int
    nodes_ready: int
    pods_total: int
    pods_running: int
    pods_pending: int
    pods_failed: int
    cpu_requests: float
    cpu_limits: float
    memory_requests: int
    memory_limits: int
    storage_usage: int
    timestamp: datetime


class ServiceMetrics(BaseModel):
    """Service-level metrics."""
    service_name: str
    requests_per_second: float
    response_time_avg: float
    response_time_p95: float
    response_time_p99: float
    error_rate_percent: float
    active_connections: int
    timestamp: datetime


class MetricsResponse(BaseModel):
    """Response containing multiple metrics."""
    system_metrics: Optional[SystemMetrics] = None
    cluster_metrics: List[ClusterMetrics] = []
    service_metrics: List[ServiceMetrics] = []
    total_count: int
    timeframe: Dict[str, datetime]


class MetricsSummary(BaseModel):
    """Summary of metrics for dashboard."""
    total_clusters: int
    healthy_clusters: int
    total_nodes: int
    ready_nodes: int
    total_pods: int
    running_pods: int
    avg_cpu_usage: float
    avg_memory_usage: float
    avg_response_time: float
    error_rate: float
    timestamp: datetime


@router.get("/system", response_model=SystemMetrics)
async def get_system_metrics(
    current_user: Dict[str, Any] = Depends(get_current_user),
    _: None = Depends(require_permission("metrics:read"))
):
    """
    Get current system metrics.
    Requires 'metrics:read' permission.
    """
    try:
        # In a real implementation, this would collect actual system metrics
        # For now, return mock data that represents a production system
        metrics = SystemMetrics(
            cpu_usage_percent=45.2,
            memory_usage_percent=68.7,
            disk_usage_percent=34.1,
            network_in_bytes=1024*1024*150,  # 150 MB
            network_out_bytes=1024*1024*89,   # 89 MB
            timestamp=datetime.utcnow()
        )
        
        logger.info(f"Retrieved system metrics for user: {current_user.get('username')}")
        return metrics
        
    except Exception as e:
        logger.error(f"Error retrieving system metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve system metrics")


@router.get("/clusters", response_model=List[ClusterMetrics])
async def get_cluster_metrics(
    cluster_id: Optional[str] = Query(None, description="Filter by cluster ID"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("metrics:read"))
):
    """
    Get cluster metrics with optional filtering.
    Requires 'metrics:read' permission.
    """
    try:
        # Get clusters from database
        query = select(KubernetesCluster)
        if cluster_id:
            query = query.where(KubernetesCluster.id == cluster_id)
        
        query = query.limit(limit)
        result = await db.execute(query)
        clusters = result.scalars().all()
        
        # Generate metrics for each cluster
        cluster_metrics = []
        for cluster in clusters:
            # In a real implementation, these would be actual metrics from the cluster
            metrics = ClusterMetrics(
                cluster_id=cluster.id,
                cluster_name=cluster.name,
                nodes_total=3,
                nodes_ready=3,
                pods_total=45,
                pods_running=42,
                pods_pending=2,
                pods_failed=1,
                cpu_requests=2.5,
                cpu_limits=8.0,
                memory_requests=4096,  # MB
                memory_limits=16384,   # MB
                storage_usage=102400,  # MB
                timestamp=datetime.utcnow()
            )
            cluster_metrics.append(metrics)
        
        logger.info(f"Retrieved metrics for {len(cluster_metrics)} clusters for user: {current_user.get('username')}")
        return cluster_metrics
        
    except Exception as e:
        logger.error(f"Error retrieving cluster metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve cluster metrics")


@router.get("/services", response_model=List[ServiceMetrics])
async def get_service_metrics(
    service_name: Optional[str] = Query(None, description="Filter by service name"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    _: None = Depends(require_permission("metrics:read"))
):
    """
    Get service metrics with optional filtering.
    Requires 'metrics:read' permission.
    """
    try:
        # List of services to generate metrics for
        services = [
            "auth-service",
            "cluster-manager-service", 
            "audit-log-service",
            "metrics-service",
            "sre-agent-service",
            "terminal-service"
        ]
        
        if service_name:
            services = [s for s in services if service_name.lower() in s.lower()]
        
        services = services[:limit]
        
        # Generate metrics for each service
        service_metrics = []
        for service in services:
            # In a real implementation, these would be actual metrics from the services
            metrics = ServiceMetrics(
                service_name=service,
                requests_per_second=45.7 if service == "auth-service" else 23.4,
                response_time_avg=125.0 if service == "auth-service" else 89.2,
                response_time_p95=250.0 if service == "auth-service" else 178.5,
                response_time_p99=450.0 if service == "auth-service" else 312.8,
                error_rate_percent=0.2 if service == "auth-service" else 0.1,
                active_connections=156 if service == "auth-service" else 89,
                timestamp=datetime.utcnow()
            )
            service_metrics.append(metrics)
        
        logger.info(f"Retrieved metrics for {len(service_metrics)} services for user: {current_user.get('username')}")
        return service_metrics
        
    except Exception as e:
        logger.error(f"Error retrieving service metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve service metrics")


@router.get("/summary", response_model=MetricsSummary)
async def get_metrics_summary(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("metrics:read"))
):
    """
    Get high-level metrics summary for dashboard.
    Requires 'metrics:read' permission.
    """
    try:
        # Get cluster count from database
        cluster_count_query = select(func.count(KubernetesCluster.id))
        cluster_result = await db.execute(cluster_count_query)
        total_clusters = cluster_result.scalar() or 0
        
        # Get healthy cluster count
        healthy_cluster_query = select(func.count(KubernetesCluster.id)).where(
            KubernetesCluster.status == "active"
        )
        healthy_result = await db.execute(healthy_cluster_query)
        healthy_clusters = healthy_result.scalar() or 0
        
        # Generate summary metrics
        summary = MetricsSummary(
            total_clusters=total_clusters,
            healthy_clusters=healthy_clusters,
            total_nodes=total_clusters * 3,  # Assume 3 nodes per cluster
            ready_nodes=healthy_clusters * 3,
            total_pods=total_clusters * 45,  # Assume 45 pods per cluster
            running_pods=healthy_clusters * 42,  # Assume 42 running pods per healthy cluster
            avg_cpu_usage=45.2,
            avg_memory_usage=68.7,
            avg_response_time=125.0,
            error_rate=0.15,
            timestamp=datetime.utcnow()
        )
        
        logger.info(f"Retrieved metrics summary for user: {current_user.get('username')}")
        return summary
        
    except Exception as e:
        logger.error(f"Error retrieving metrics summary: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve metrics summary")


@router.get("/timeseries")
async def get_timeseries_metrics(
    metric_name: str = Query(..., description="Name of the metric to retrieve"),
    start_time: Optional[datetime] = Query(None, description="Start time for the time series"),
    end_time: Optional[datetime] = Query(None, description="End time for the time series"),
    resolution: str = Query("1m", description="Resolution for data points (1m, 5m, 1h, 1d)"),
    cluster_id: Optional[str] = Query(None, description="Filter by cluster ID"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    _: None = Depends(require_permission("metrics:read"))
):
    """
    Get time series metrics data.
    Requires 'metrics:read' permission.
    """
    try:
        # Set default time range if not provided
        if not end_time:
            end_time = datetime.utcnow()
        if not start_time:
            start_time = end_time - timedelta(hours=1)
        
        # Generate time series data points
        data_points = []
        current_time = start_time
        
        while current_time <= end_time:
            # Generate mock metric values based on metric name
            if metric_name == "cpu_usage":
                value = 45.0 + (hash(str(current_time)) % 20 - 10)  # 35-55% range
            elif metric_name == "memory_usage":
                value = 68.0 + (hash(str(current_time)) % 15 - 7)   # 61-75% range
            elif metric_name == "response_time":
                value = 125.0 + (hash(str(current_time)) % 50 - 25) # 100-150ms range
            else:
                value = 50.0 + (hash(str(current_time)) % 40 - 20)  # Generic 30-70 range
            
            data_point = MetricDataPoint(
                timestamp=current_time,
                value=max(0, value),  # Ensure non-negative values
                labels={"cluster_id": cluster_id} if cluster_id else {}
            )
            data_points.append(data_point)
            
            # Increment time based on resolution
            if resolution == "1m":
                current_time += timedelta(minutes=1)
            elif resolution == "5m":
                current_time += timedelta(minutes=5)
            elif resolution == "1h":
                current_time += timedelta(hours=1)
            elif resolution == "1d":
                current_time += timedelta(days=1)
            else:
                current_time += timedelta(minutes=1)  # Default to 1 minute
        
        logger.info(f"Retrieved {len(data_points)} time series data points for metric: {metric_name}")
        return {
            "metric_name": metric_name,
            "start_time": start_time,
            "end_time": end_time,
            "resolution": resolution,
            "data_points": data_points,
            "total_points": len(data_points)
        }
        
    except Exception as e:
        logger.error(f"Error retrieving time series metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve time series metrics")


@router.post("/collect")
async def trigger_metrics_collection(
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _: None = Depends(require_permission("metrics:write"))
):
    """
    Trigger manual metrics collection.
    Requires 'metrics:write' permission.
    """
    try:
        # Add background task for metrics collection
        background_tasks.add_task(collect_metrics_background)
        
        logger.info(f"Triggered metrics collection by user: {current_user.get('username')}")
        return {
            "message": "Metrics collection triggered successfully",
            "status": "initiated",
            "timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"Error triggering metrics collection: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to trigger metrics collection")


async def collect_metrics_background():
    """Background task for collecting metrics."""
    try:
        logger.info("Starting background metrics collection")
        
        # Simulate metrics collection process
        await asyncio.sleep(2)  # Simulate collection time
        
        logger.info("Background metrics collection completed")
        
    except Exception as e:
        logger.error(f"Error in background metrics collection: {str(e)}")


@router.get("/health-metrics")
async def get_health_metrics(
    current_user: Dict[str, Any] = Depends(get_current_user),
    _: None = Depends(require_permission("metrics:read"))
):
    """
    Get health-related metrics for all services.
    Requires 'metrics:read' permission.
    """
    try:
        # Generate health metrics for all services
        services = [
            {"name": "auth-service", "status": "healthy", "uptime": "3h 15m", "response_time": "45ms"},
            {"name": "cluster-manager-service", "status": "healthy", "uptime": "3h 12m", "response_time": "67ms"},
            {"name": "audit-log-service", "status": "healthy", "uptime": "15m", "response_time": "34ms"},
            {"name": "metrics-service", "status": "healthy", "uptime": "2m", "response_time": "23ms"},
            {"name": "postgres", "status": "healthy", "uptime": "21h", "response_time": "12ms"},
            {"name": "redis", "status": "healthy", "uptime": "21h", "response_time": "5ms"}
        ]
        
        health_metrics = {
            "timestamp": datetime.utcnow(),
            "services": services,
            "overall_health": "healthy",
            "total_services": len(services),
            "healthy_services": len([s for s in services if s["status"] == "healthy"]),
            "avg_response_time": "31ms"
        }
        
        logger.info(f"Retrieved health metrics for user: {current_user.get('username')}")
        return health_metrics
        
    except Exception as e:
        logger.error(f"Error retrieving health metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve health metrics") 