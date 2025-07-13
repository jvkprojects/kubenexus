"""
Clusters router for KubeNexus Cluster Manager Service.
Handles CRUD operations for Kubernetes clusters across cloud providers.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from uuid import uuid4
import yaml
import json
import asyncio
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, text, and_
from sqlalchemy.orm import joinedload
from pydantic import BaseModel, Field, validator

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    get_settings,
    KubernetesCluster,
    CloudProvider,
    audit_logger,
    get_current_user,
    require_permission,
    kubeconfig_manager,
    cloud_config_manager
)

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()


# Pydantic models
class ClusterCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    cluster_type: str = Field(..., pattern=r"^(on_premise|eks|gke|aks)$")
    region: Optional[str] = None
    kubeconfig: Optional[str] = None
    cloud_provider_id: Optional[str] = None
    cloud_provider_config: Optional[Dict[str, Any]] = None
    tags: Optional[Dict[str, str]] = {}
    
    @validator('name')
    def validate_name(cls, v):
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Name can only contain letters, numbers, hyphens, and underscores')
        return v.lower()
    
    @validator('cluster_type')
    def validate_cluster_type_requirements(cls, v, values):
        if v == 'on_premise' and not values.get('kubeconfig'):
            raise ValueError('Kubeconfig is required for on-premise clusters')
        elif v in ['eks', 'gke', 'aks'] and not values.get('cloud_provider_id'):
            raise ValueError('Cloud provider ID is required for managed clusters')
        return v


class ClusterUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    kubeconfig: Optional[str] = None
    cloud_provider_config: Optional[Dict[str, Any]] = None
    tags: Optional[Dict[str, str]] = None
    
    @validator('name')
    def validate_name(cls, v):
        if v and not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Name can only contain letters, numbers, hyphens, and underscores')
        return v.lower() if v else v


class ClusterResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    type: str
    status: str
    region: Optional[str]
    version: Optional[str]
    node_count: int
    api_endpoint: Optional[str]
    cloud_provider: Optional[Dict[str, Any]]
    tags: Dict[str, str]
    last_health_check: Optional[datetime]
    health_check_error: Optional[str]
    created_at: datetime
    updated_at: datetime
    created_by: str


class ClusterListResponse(BaseModel):
    clusters: List[ClusterResponse]
    total: int
    page: int
    size: int
    pages: int


class ClusterHealthStatus(BaseModel):
    cluster_id: str
    status: str
    healthy: bool
    node_count: int
    ready_nodes: int
    version: str
    last_check: datetime
    errors: List[str]
    warnings: List[str]


class ClusterMetrics(BaseModel):
    cluster_id: str
    cpu_usage: float
    memory_usage: float
    storage_usage: float
    network_in: float
    network_out: float
    pod_count: int
    service_count: int
    namespace_count: int
    timestamp: datetime


@router.get("/health")
async def clusters_health():
    """Health check for clusters router."""
    return {
        "status": "healthy", 
        "service": "cluster-manager-service", 
        "router": "clusters",
        "timestamp": datetime.now(timezone.utc)
    }


@router.get("/", response_model=ClusterListResponse)
async def list_clusters(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    cluster_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    cloud_provider_id: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cluster:read"))
):
    """List clusters with advanced filtering and pagination."""
    
    try:
        # Build base query
        query = select(KubernetesCluster).options(
            joinedload(KubernetesCluster.cloud_provider),
            joinedload(KubernetesCluster.creator)
        )
        
        # Apply filters
        conditions = []
        
        if search:
            conditions.append(
                or_(
                    KubernetesCluster.name.ilike(f"%{search}%"),
                    KubernetesCluster.description.ilike(f"%{search}%")
                )
            )
        
        if cluster_type:
            conditions.append(KubernetesCluster.type == cluster_type)
        
        if status:
            conditions.append(KubernetesCluster.status == status)
        
        if cloud_provider_id:
            conditions.append(KubernetesCluster.cloud_provider_id == cloud_provider_id)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Get total count
        count_query = select(func.count(KubernetesCluster.id))
        if conditions:
            count_query = count_query.where(and_(*conditions))
        
        count_result = await db.execute(count_query)
        total = count_result.scalar()
        
        # Apply pagination
        offset = (page - 1) * size
        query = query.offset(offset).limit(size).order_by(KubernetesCluster.created_at.desc())
        
        result = await db.execute(query)
        clusters = result.scalars().all()
        
        # Format response
        cluster_responses = []
        for cluster in clusters:
            cloud_provider_info = None
            if cluster.cloud_provider:
                cloud_provider_info = {
                    "id": str(cluster.cloud_provider.id),
                    "name": cluster.cloud_provider.name,
                    "type": cluster.cloud_provider.provider_type,
                    "status": cluster.cloud_provider.status
                }
            
            cluster_responses.append(ClusterResponse(
                id=str(cluster.id),
                name=cluster.name,
                description=cluster.description,
                type=cluster.type,
                status=cluster.status,
                region=cluster.cloud_provider_config.get("region") if cluster.cloud_provider_config else None,
                version=cluster.version,
                node_count=cluster.node_count,
                api_endpoint=cluster.api_endpoint,
                cloud_provider=cloud_provider_info,
                tags=cluster.cloud_provider_config.get("tags", {}) if cluster.cloud_provider_config else {},
                last_health_check=cluster.last_health_check,
                health_check_error=cluster.health_check_error,
                created_at=cluster.created_at,
                updated_at=cluster.updated_at,
                created_by=str(cluster.created_by)
            ))
        
        pages = (total + size - 1) // size
        
        return ClusterListResponse(
            clusters=cluster_responses,
            total=total,
            page=page,
            size=size,
            pages=pages
        )
        
    except Exception as e:
        logger.error(f"Failed to list clusters: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list clusters"
        )


@router.get("/{cluster_id}", response_model=ClusterResponse)
async def get_cluster(
    cluster_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cluster:read"))
):
    """Get cluster by ID with detailed information."""
    
    try:
        result = await db.execute(
            select(KubernetesCluster)
            .options(
                joinedload(KubernetesCluster.cloud_provider),
                joinedload(KubernetesCluster.creator)
            )
            .where(KubernetesCluster.id == cluster_id)
        )
        cluster = result.scalar_one_or_none()
        
        if not cluster:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cluster not found"
            )
        
        # Format cloud provider info
        cloud_provider_info = None
        if cluster.cloud_provider:
            cloud_provider_info = {
                "id": str(cluster.cloud_provider.id),
                "name": cluster.cloud_provider.name,
                "type": cluster.cloud_provider.provider_type,
                "status": cluster.cloud_provider.status
            }
        
        return ClusterResponse(
            id=str(cluster.id),
            name=cluster.name,
            description=cluster.description,
            type=cluster.type,
            status=cluster.status,
            region=cluster.cloud_provider_config.get("region") if cluster.cloud_provider_config else None,
            version=cluster.version,
            node_count=cluster.node_count,
            api_endpoint=cluster.api_endpoint,
            cloud_provider=cloud_provider_info,
            tags=cluster.cloud_provider_config.get("tags", {}) if cluster.cloud_provider_config else {},
            last_health_check=cluster.last_health_check,
            health_check_error=cluster.health_check_error,
            created_at=cluster.created_at,
            updated_at=cluster.updated_at,
            created_by=str(cluster.created_by)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get cluster: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get cluster"
        )


@router.post("/", response_model=ClusterResponse)
async def create_cluster(
    cluster_data: ClusterCreate,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cluster:create"))
):
    """Create a new cluster with cloud provider integration."""
    
    try:
        # Check if cluster name already exists
        result = await db.execute(
            select(KubernetesCluster).where(KubernetesCluster.name == cluster_data.name)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cluster name already exists"
            )
        
        # Validate cloud provider if specified
        cloud_provider = None
        if cluster_data.cloud_provider_id:
            result = await db.execute(
                select(CloudProvider).where(CloudProvider.id == cluster_data.cloud_provider_id)
            )
            cloud_provider = result.scalar_one_or_none()
            if not cloud_provider:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Cloud provider not found"
                )
        
        # Encrypt kubeconfig if provided
        encrypted_kubeconfig = None
        if cluster_data.kubeconfig:
            encrypted_kubeconfig = kubeconfig_manager.encrypt_kubeconfig(cluster_data.kubeconfig)
        
        # Encrypt cloud provider config if provided
        encrypted_cloud_config = None
        if cluster_data.cloud_provider_config:
            encrypted_cloud_config = cloud_config_manager.encrypt_cloud_config(
                cluster_data.cloud_provider_config
            )
        
        # Create cluster
        cluster = KubernetesCluster(
            id=uuid4(),
            name=cluster_data.name,
            description=cluster_data.description,
            type=cluster_data.cluster_type,
            status='pending',
            kubeconfig=encrypted_kubeconfig,
            cloud_provider_id=cluster_data.cloud_provider_id,
            cloud_provider_config=encrypted_cloud_config,
            created_by=current_user["id"]
        )
        
        db.add(cluster)
        await db.commit()
        await db.refresh(cluster)
        
        # Log cluster creation
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="create",
            resource_type="cluster",
            resource_id=str(cluster.id),
            resource_name=cluster.name,
            success=True,
            additional_data={
                "cluster_type": cluster_data.cluster_type,
                "cloud_provider_id": cluster_data.cloud_provider_id,
                "region": cluster_data.region
            }
        )
        
        # Schedule health check
        background_tasks.add_task(perform_cluster_health_check, str(cluster.id))
        
        logger.info(f"Cluster {cluster.name} created by {current_user['username']}")
        
        # Format response
        cloud_provider_info = None
        if cloud_provider:
            cloud_provider_info = {
                "id": str(cloud_provider.id),
                "name": cloud_provider.name,
                "type": cloud_provider.provider_type,
                "status": cloud_provider.status
            }
        
        return ClusterResponse(
            id=str(cluster.id),
            name=cluster.name,
            description=cluster.description,
            type=cluster.type,
            status=cluster.status,
            region=cluster_data.region,
            version=cluster.version,
            node_count=cluster.node_count,
            api_endpoint=cluster.api_endpoint,
            cloud_provider=cloud_provider_info,
            tags=cluster_data.tags or {},
            last_health_check=cluster.last_health_check,
            health_check_error=cluster.health_check_error,
            created_at=cluster.created_at,
            updated_at=cluster.updated_at,
            created_by=str(cluster.created_by)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create cluster: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create cluster"
        )


@router.put("/{cluster_id}", response_model=ClusterResponse)
async def update_cluster(
    cluster_id: str,
    cluster_data: ClusterUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cluster:update"))
):
    """Update cluster configuration."""
    
    try:
        # Get existing cluster
        result = await db.execute(
            select(KubernetesCluster)
            .options(joinedload(KubernetesCluster.cloud_provider))
            .where(KubernetesCluster.id == cluster_id)
        )
        cluster = result.scalar_one_or_none()
        
        if not cluster:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cluster not found"
            )
        
        # Check for name conflicts
        if cluster_data.name and cluster_data.name != cluster.name:
            result = await db.execute(
                select(KubernetesCluster).where(KubernetesCluster.name == cluster_data.name)
            )
            if result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cluster name already exists"
                )
        
        # Update fields
        update_data = {}
        if cluster_data.name:
            update_data["name"] = cluster_data.name
        if cluster_data.description is not None:
            update_data["description"] = cluster_data.description
        if cluster_data.kubeconfig:
            update_data["kubeconfig"] = kubeconfig_manager.encrypt_kubeconfig(cluster_data.kubeconfig)
        if cluster_data.cloud_provider_config:
            update_data["cloud_provider_config"] = cloud_config_manager.encrypt_cloud_config(
                cluster_data.cloud_provider_config
            )
        
        # Apply updates
        for key, value in update_data.items():
            setattr(cluster, key, value)
        
        await db.commit()
        await db.refresh(cluster)
        
        # Log update
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="update",
            resource_type="cluster",
            resource_id=str(cluster.id),
            resource_name=cluster.name,
            success=True,
            additional_data=update_data
        )
        
        logger.info(f"Cluster {cluster.name} updated by {current_user['username']}")
        
        # Format response
        cloud_provider_info = None
        if cluster.cloud_provider:
            cloud_provider_info = {
                "id": str(cluster.cloud_provider.id),
                "name": cluster.cloud_provider.name,
                "type": cluster.cloud_provider.provider_type,
                "status": cluster.cloud_provider.status
            }
        
        return ClusterResponse(
            id=str(cluster.id),
            name=cluster.name,
            description=cluster.description,
            type=cluster.type,
            status=cluster.status,
            region=cluster.cloud_provider_config.get("region") if cluster.cloud_provider_config else None,
            version=cluster.version,
            node_count=cluster.node_count,
            api_endpoint=cluster.api_endpoint,
            cloud_provider=cloud_provider_info,
            tags=cluster.cloud_provider_config.get("tags", {}) if cluster.cloud_provider_config else {},
            last_health_check=cluster.last_health_check,
            health_check_error=cluster.health_check_error,
            created_at=cluster.created_at,
            updated_at=cluster.updated_at,
            created_by=str(cluster.created_by)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update cluster: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update cluster"
        )


@router.delete("/{cluster_id}")
async def delete_cluster(
    cluster_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cluster:delete"))
):
    """Delete a cluster."""
    
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
        
        cluster_name = cluster.name
        
        # Delete cluster
        await db.delete(cluster)
        await db.commit()
        
        # Log deletion
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="delete",
            resource_type="cluster",
            resource_id=cluster_id,
            resource_name=cluster_name,
            success=True
        )
        
        logger.info(f"Cluster {cluster_name} deleted by {current_user['username']}")
        
        return {"message": "Cluster deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete cluster: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete cluster"
        )


@router.post("/{cluster_id}/health-check", response_model=ClusterHealthStatus)
async def check_cluster_health(
    cluster_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cluster:read"))
):
    """Perform health check on cluster."""
    
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
        
        # Perform health check
        health_status = await perform_cluster_health_check(cluster_id)
        
        return health_status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to check cluster health: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check cluster health"
        )


# Background tasks and utility functions
async def perform_cluster_health_check(cluster_id: str) -> ClusterHealthStatus:
    """Perform comprehensive health check on a cluster."""
    
    try:
        # Get cluster from database
        from shared import get_async_db_dependency
        
        async with get_async_db_dependency() as db:
            result = await db.execute(
                select(KubernetesCluster).where(KubernetesCluster.id == cluster_id)
            )
            cluster = result.scalar_one_or_none()
            
            if not cluster:
                raise ValueError(f"Cluster {cluster_id} not found")
            
            errors = []
            warnings = []
            healthy = False
            node_count = 0
            ready_nodes = 0
            version = "unknown"
            
            try:
                # Load kubeconfig
                if cluster.kubeconfig:
                    kubeconfig_dict = kubeconfig_manager.decrypt_kubeconfig_to_dict(cluster.kubeconfig)
                    
                    # Create Kubernetes client
                    configuration = client.Configuration()
                    config.load_kube_config_from_dict(kubeconfig_dict, client_configuration=configuration)
                    
                    with client.ApiClient(configuration) as api_client:
                        # Check cluster version
                        version_api = client.VersionApi(api_client)
                        version_info = version_api.get_code()
                        version = version_info.git_version
                        
                        # Check nodes
                        core_api = client.CoreV1Api(api_client)
                        nodes = core_api.list_node()
                        node_count = len(nodes.items)
                        
                        for node in nodes.items:
                            if node.status.conditions:
                                for condition in node.status.conditions:
                                    if condition.type == "Ready" and condition.status == "True":
                                        ready_nodes += 1
                                        break
                        
                        healthy = ready_nodes > 0
                        
                        # Update cluster in database
                        cluster.status = 'connected' if healthy else 'error'
                        cluster.version = version
                        cluster.node_count = node_count
                        cluster.last_health_check = datetime.now(timezone.utc)
                        cluster.health_check_error = None if healthy else "Some nodes are not ready"
                        
                        await db.commit()
                        
                else:
                    errors.append("No kubeconfig available")
                    
            except Exception as e:
                errors.append(f"Kubernetes API error: {str(e)}")
                
                # Update cluster error status
                cluster.status = 'error'
                cluster.last_health_check = datetime.now(timezone.utc)
                cluster.health_check_error = str(e)
                await db.commit()
            
            return ClusterHealthStatus(
                cluster_id=cluster_id,
                status=cluster.status,
                healthy=healthy,
                node_count=node_count,
                ready_nodes=ready_nodes,
                version=version,
                last_check=cluster.last_health_check or datetime.now(timezone.utc),
                errors=errors,
                warnings=warnings
            )
            
    except Exception as e:
        logger.error(f"Health check failed for cluster {cluster_id}: {e}", exc_info=True)
        return ClusterHealthStatus(
            cluster_id=cluster_id,
            status="error",
            healthy=False,
            node_count=0,
            ready_nodes=0,
            version="unknown",
            last_check=datetime.now(timezone.utc),
            errors=[str(e)],
            warnings=[]
        ) 