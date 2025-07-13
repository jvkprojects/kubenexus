"""
Cloud Providers router for KubeNexus Cluster Manager Service.
Handles CRUD operations for cloud provider configurations (AWS, Azure, GCP).
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from pydantic import BaseModel, Field, validator
import json
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared import (
    get_async_db_dependency,
    get_logger,
    get_settings,
    CloudProvider,
    CloudCredentialsManager,
    audit_logger,
    require_permission,
    get_current_user
)

router = APIRouter()
logger = get_logger(__name__)
settings = get_settings()


# Pydantic models
class CloudProviderCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    provider_type: str = Field(..., pattern=r"^(aws|azure|gcp)$")
    description: Optional[str] = Field(None, max_length=1000)
    credentials: Dict[str, Any] = Field(..., min_items=1)
    regions: List[str] = []
    tags: Optional[Dict[str, str]] = {}
    
    @validator('name')
    def validate_name(cls, v):
        if not v.replace('-', '').replace('_', '').replace(' ', '').isalnum():
            raise ValueError('Name can only contain letters, numbers, spaces, hyphens, and underscores')
        return v


class CloudProviderUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    credentials: Optional[Dict[str, Any]] = None
    regions: Optional[List[str]] = None
    status: Optional[str] = Field(None, pattern=r"^(active|inactive|error)$")
    tags: Optional[Dict[str, str]] = None
    
    @validator('name')
    def validate_name(cls, v):
        if v is not None and not v.replace('-', '').replace('_', '').replace(' ', '').isalnum():
            raise ValueError('Name can only contain letters, numbers, spaces, hyphens, and underscores')
        return v


class CloudProviderResponse(BaseModel):
    id: str
    name: str
    provider_type: str
    description: Optional[str]
    regions: List[str]
    status: str
    tags: Dict[str, str]
    created_at: datetime
    updated_at: datetime
    last_validated: Optional[datetime]


class CloudProviderListResponse(BaseModel):
    providers: List[CloudProviderResponse]
    total: int
    page: int
    size: int
    pages: int


class CloudProviderValidation(BaseModel):
    provider_id: str
    status: str
    regions: List[Dict[str, Any]]
    validation_errors: List[str]
    last_validated: datetime


class RegionInfo(BaseModel):
    name: str
    display_name: str
    availability_zones: List[str]
    services: List[str]


@router.post("/", response_model=CloudProviderResponse)
async def create_cloud_provider(
    provider_data: CloudProviderCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cloud_provider:create"))
):
    """Create a new cloud provider configuration."""
    
    try:
        # Check if provider name already exists
        result = await db.execute(
            select(CloudProvider).where(CloudProvider.name == provider_data.name)
        )
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cloud provider name already exists"
            )
        
        # Validate credentials format based on provider type
        _validate_credentials_format(provider_data.provider_type, provider_data.credentials)
        
        # Test credentials (optional validation)
        validation_result = await _validate_cloud_credentials(
            provider_data.provider_type, 
            provider_data.credentials
        )
        
        # Encrypt credentials
        encrypted_credentials = CloudCredentialsManager.encrypt_credentials(
            provider_data.provider_type,
            provider_data.credentials
        )
        
        # Create cloud provider
        provider = CloudProvider(
            id=str(uuid4()),
            name=provider_data.name,
            provider_type=provider_data.provider_type,
            description=provider_data.description,
            credentials_encrypted=encrypted_credentials,
            regions=provider_data.regions,
            status='active' if validation_result["valid"] else 'error',
            tags=provider_data.tags or {},
            last_validated=datetime.now(timezone.utc) if validation_result["valid"] else None
        )
        
        db.add(provider)
        await db.commit()
        await db.refresh(provider)
        
        # Log provider creation
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="create",
            resource_type="cloud_provider",
            resource_id=provider.id,
            resource_name=provider.name,
            success=True,
            additional_data={
                "provider_type": provider_data.provider_type,
                "regions": provider_data.regions,
                "validation_status": validation_result["valid"]
            }
        )
        
        logger.info(f"Cloud provider {provider.name} created by {current_user['username']}")
        
        return _format_provider_response(provider)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create cloud provider: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create cloud provider"
        )


@router.get("/", response_model=CloudProviderListResponse)
async def list_cloud_providers(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    provider_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cloud_provider:read"))
):
    """List cloud providers with filtering and pagination."""
    
    try:
        # Build query
        query = select(CloudProvider)
        
        conditions = []
        
        # Apply filters
        if search:
            search_term = f"%{search}%"
            conditions.append(
                or_(
                    CloudProvider.name.ilike(search_term),
                    CloudProvider.description.ilike(search_term)
                )
            )
        
        if provider_type:
            conditions.append(CloudProvider.provider_type == provider_type)
        
        if status:
            conditions.append(CloudProvider.status == status)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        # Get total count
        count_query = select(func.count(CloudProvider.id))
        if conditions:
            count_query = count_query.where(and_(*conditions))
        
        result = await db.execute(count_query)
        total = result.scalar()
        
        # Apply pagination
        offset = (page - 1) * size
        query = query.offset(offset).limit(size)
        
        # Execute query
        result = await db.execute(query)
        providers = result.scalars().all()
        
        # Calculate pagination info
        pages = (total + size - 1) // size
        
        return CloudProviderListResponse(
            providers=[_format_provider_response(provider) for provider in providers],
            total=total,
            page=page,
            size=size,
            pages=pages
        )
        
    except Exception as e:
        logger.error(f"Failed to list cloud providers: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list cloud providers"
        )


@router.get("/{provider_id}", response_model=CloudProviderResponse)
async def get_cloud_provider(
    provider_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cloud_provider:read"))
):
    """Get cloud provider by ID."""
    
    try:
        result = await db.execute(
            select(CloudProvider).where(CloudProvider.id == provider_id)
        )
        provider = result.scalar_one_or_none()
        
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cloud provider not found"
            )
        
        return _format_provider_response(provider)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get cloud provider {provider_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get cloud provider"
        )


@router.put("/{provider_id}", response_model=CloudProviderResponse)
async def update_cloud_provider(
    provider_id: str,
    provider_data: CloudProviderUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cloud_provider:update"))
):
    """Update cloud provider configuration."""
    
    try:
        # Get existing provider
        result = await db.execute(
            select(CloudProvider).where(CloudProvider.id == provider_id)
        )
        provider = result.scalar_one_or_none()
        
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cloud provider not found"
            )
        
        # Check name uniqueness if changed
        if provider_data.name and provider_data.name != provider.name:
            result = await db.execute(
                select(CloudProvider).where(
                    and_(CloudProvider.name == provider_data.name, CloudProvider.id != provider_id)
                )
            )
            if result.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Cloud provider name already exists"
                )
        
        # Update credentials if provided
        if provider_data.credentials:
            _validate_credentials_format(provider.provider_type, provider_data.credentials)
            
            # Test new credentials
            validation_result = await _validate_cloud_credentials(
                provider.provider_type, 
                provider_data.credentials
            )
            
            # Encrypt new credentials
            provider.credentials_encrypted = CloudCredentialsManager.encrypt_credentials(
                provider.provider_type,
                provider_data.credentials
            )
            
            provider.status = 'active' if validation_result["valid"] else 'error'
            provider.last_validated = datetime.now(timezone.utc) if validation_result["valid"] else None
        
        # Update other fields
        if provider_data.name is not None:
            provider.name = provider_data.name
        if provider_data.description is not None:
            provider.description = provider_data.description
        if provider_data.regions is not None:
            provider.regions = provider_data.regions
        if provider_data.status is not None:
            provider.status = provider_data.status
        if provider_data.tags is not None:
            provider.tags = provider_data.tags
        
        provider.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(provider)
        
        # Log provider update
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="update",
            resource_type="cloud_provider",
            resource_id=provider.id,
            resource_name=provider.name,
            success=True,
            additional_data={
                "updated_fields": provider_data.dict(exclude_unset=True)
            }
        )
        
        logger.info(f"Cloud provider {provider.name} updated by {current_user['username']}")
        
        return _format_provider_response(provider)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update cloud provider {provider_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update cloud provider"
        )


@router.delete("/{provider_id}")
async def delete_cloud_provider(
    provider_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cloud_provider:delete"))
):
    """Delete cloud provider configuration."""
    
    try:
        # Get provider
        result = await db.execute(
            select(CloudProvider).where(CloudProvider.id == provider_id)
        )
        provider = result.scalar_one_or_none()
        
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cloud provider not found"
            )
        
        # Check if provider is used by any clusters
        from shared import Cluster
        result = await db.execute(
            select(func.count(Cluster.id)).where(Cluster.cloud_provider_id == provider_id)
        )
        cluster_count = result.scalar()
        
        if cluster_count > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot delete cloud provider. It is used by {cluster_count} cluster(s)."
            )
        
        provider_name = provider.name
        
        # Delete provider
        await db.delete(provider)
        await db.commit()
        
        # Log provider deletion
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="delete",
            resource_type="cloud_provider",
            resource_id=provider_id,
            resource_name=provider_name,
            success=True
        )
        
        logger.info(f"Cloud provider {provider_name} deleted by {current_user['username']}")
        
        return {"message": "Cloud provider deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete cloud provider {provider_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete cloud provider"
        )


@router.post("/{provider_id}/validate", response_model=CloudProviderValidation)
async def validate_cloud_provider(
    provider_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cloud_provider:update"))
):
    """Validate cloud provider credentials and connectivity."""
    
    try:
        # Get provider
        result = await db.execute(
            select(CloudProvider).where(CloudProvider.id == provider_id)
        )
        provider = result.scalar_one_or_none()
        
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cloud provider not found"
            )
        
        # Decrypt credentials
        credentials = CloudCredentialsManager.decrypt_credentials(
            provider.provider_type,
            provider.credentials_encrypted
        )
        
        # Validate credentials
        validation_result = await _validate_cloud_credentials(
            provider.provider_type,
            credentials
        )
        
        # Get regions info
        regions_info = await _get_provider_regions(provider.provider_type, credentials)
        
        # Update provider status
        provider.status = 'active' if validation_result["valid"] else 'error'
        provider.last_validated = datetime.now(timezone.utc)
        await db.commit()
        
        # Log validation
        audit_logger.log_user_action(
            user_id=current_user["id"],
            action="validate",
            resource_type="cloud_provider",
            resource_id=provider.id,
            resource_name=provider.name,
            success=validation_result["valid"],
            additional_data={
                "validation_errors": validation_result.get("errors", [])
            }
        )
        
        return CloudProviderValidation(
            provider_id=provider_id,
            status="valid" if validation_result["valid"] else "invalid",
            regions=regions_info,
            validation_errors=validation_result.get("errors", []),
            last_validated=datetime.now(timezone.utc)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to validate cloud provider {provider_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate cloud provider"
        )


@router.get("/{provider_id}/regions", response_model=List[RegionInfo])
async def get_provider_regions(
    provider_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_dependency),
    _: None = Depends(require_permission("cloud_provider:read"))
):
    """Get available regions for a cloud provider."""
    
    try:
        # Get provider
        result = await db.execute(
            select(CloudProvider).where(CloudProvider.id == provider_id)
        )
        provider = result.scalar_one_or_none()
        
        if not provider:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Cloud provider not found"
            )
        
        # Decrypt credentials
        credentials = CloudCredentialsManager.decrypt_credentials(
            provider.provider_type,
            provider.credentials_encrypted
        )
        
        # Get regions
        regions_info = await _get_provider_regions(provider.provider_type, credentials)
        
        return [
            RegionInfo(
                name=region["name"],
                display_name=region.get("display_name", region["name"]),
                availability_zones=region.get("availability_zones", []),
                services=region.get("services", [])
            )
            for region in regions_info
        ]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get regions for provider {provider_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get provider regions"
        )


def _validate_credentials_format(provider_type: str, credentials: Dict[str, Any]) -> None:
    """Validate credentials format based on provider type."""
    
    required_fields = {
        "aws": ["access_key_id", "secret_access_key"],
        "azure": ["subscription_id", "client_id", "client_secret", "tenant_id"],
        "gcp": ["project_id", "service_account_key"]
    }
    
    if provider_type not in required_fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider type: {provider_type}"
        )
    
    missing_fields = []
    for field in required_fields[provider_type]:
        if field not in credentials or not credentials[field]:
            missing_fields.append(field)
    
    if missing_fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing required credential fields: {', '.join(missing_fields)}"
        )


async def _validate_cloud_credentials(provider_type: str, credentials: Dict[str, Any]) -> Dict[str, Any]:
    """Validate cloud provider credentials by testing API connectivity."""
    
    try:
        if provider_type == "aws":
            return await _validate_aws_credentials(credentials)
        elif provider_type == "azure":
            return await _validate_azure_credentials(credentials)
        elif provider_type == "gcp":
            return await _validate_gcp_credentials(credentials)
        else:
            return {"valid": False, "errors": ["Unsupported provider type"]}
    
    except Exception as e:
        logger.error(f"Credential validation failed for {provider_type}: {e}")
        return {"valid": False, "errors": [str(e)]}


async def _validate_aws_credentials(credentials: Dict[str, Any]) -> Dict[str, Any]:
    """Validate AWS credentials."""
    
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        
        # Create STS client to test credentials
        sts_client = boto3.client(
            'sts',
            aws_access_key_id=credentials["access_key_id"],
            aws_secret_access_key=credentials["secret_access_key"],
            region_name='us-east-1'
        )
        
        # Test credentials by getting caller identity
        response = sts_client.get_caller_identity()
        
        return {
            "valid": True,
            "account_id": response.get("Account"),
            "user_id": response.get("UserId")
        }
        
    except (ClientError, NoCredentialsError) as e:
        return {"valid": False, "errors": [str(e)]}
    except Exception as e:
        return {"valid": False, "errors": [f"AWS validation error: {str(e)}"]}


async def _validate_azure_credentials(credentials: Dict[str, Any]) -> Dict[str, Any]:
    """Validate Azure credentials."""
    
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resource import ResourceManagementClient
        
        # Create credential object
        credential = ClientSecretCredential(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"]
        )
        
        # Test credentials by listing resource groups
        resource_client = ResourceManagementClient(
            credential,
            credentials["subscription_id"]
        )
        
        # Try to list resource groups (this will fail if credentials are invalid)
        list(resource_client.resource_groups.list())
        
        return {"valid": True}
        
    except Exception as e:
        return {"valid": False, "errors": [f"Azure validation error: {str(e)}"]}


async def _validate_gcp_credentials(credentials: Dict[str, Any]) -> Dict[str, Any]:
    """Validate GCP credentials."""
    
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        import json
        
        # Parse service account key
        if isinstance(credentials["service_account_key"], str):
            key_data = json.loads(credentials["service_account_key"])
        else:
            key_data = credentials["service_account_key"]
        
        # Create credentials
        creds = service_account.Credentials.from_service_account_info(key_data)
        
        # Test credentials by listing projects
        service = build('cloudresourcemanager', 'v1', credentials=creds)
        
        # Try to get project info
        project = service.projects().get(projectId=credentials["project_id"]).execute()
        
        return {
            "valid": True,
            "project_name": project.get("name"),
            "project_number": project.get("projectNumber")
        }
        
    except Exception as e:
        return {"valid": False, "errors": [f"GCP validation error: {str(e)}"]}


async def _get_provider_regions(provider_type: str, credentials: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get available regions for a cloud provider."""
    
    try:
        if provider_type == "aws":
            return await _get_aws_regions(credentials)
        elif provider_type == "azure":
            return await _get_azure_regions(credentials)
        elif provider_type == "gcp":
            return await _get_gcp_regions(credentials)
        else:
            return []
    
    except Exception as e:
        logger.error(f"Failed to get regions for {provider_type}: {e}")
        return []


async def _get_aws_regions(credentials: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get AWS regions."""
    
    try:
        import boto3
        
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=credentials["access_key_id"],
            aws_secret_access_key=credentials["secret_access_key"],
            region_name='us-east-1'
        )
        
        response = ec2_client.describe_regions()
        
        regions = []
        for region in response['Regions']:
            regions.append({
                "name": region['RegionName'],
                "display_name": region['RegionName'],
                "availability_zones": [],  # Would need separate API call
                "services": ["ec2", "eks", "rds", "s3"]
            })
        
        return regions
        
    except Exception as e:
        logger.error(f"Failed to get AWS regions: {e}")
        return []


async def _get_azure_regions(credentials: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get Azure regions."""
    
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.resource import ResourceManagementClient
        
        credential = ClientSecretCredential(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"]
        )
        
        resource_client = ResourceManagementClient(
            credential,
            credentials["subscription_id"]
        )
        
        # Get subscription to find available locations
        subscription = resource_client.subscriptions.get(credentials["subscription_id"])
        
        regions = []
        # Mock regions for now - would use actual Azure API
        azure_regions = ["eastus", "westus", "westeurope", "eastasia"]
        for region in azure_regions:
            regions.append({
                "name": region,
                "display_name": region.replace("us", " US").replace("europe", " Europe").title(),
                "availability_zones": [],
                "services": ["aks", "compute", "storage"]
            })
        
        return regions
        
    except Exception as e:
        logger.error(f"Failed to get Azure regions: {e}")
        return []


async def _get_gcp_regions(credentials: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get GCP regions."""
    
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        import json
        
        # Parse service account key
        if isinstance(credentials["service_account_key"], str):
            key_data = json.loads(credentials["service_account_key"])
        else:
            key_data = credentials["service_account_key"]
        
        creds = service_account.Credentials.from_service_account_info(key_data)
        service = build('compute', 'v1', credentials=creds)
        
        # Get regions
        request = service.regions().list(project=credentials["project_id"])
        response = request.execute()
        
        regions = []
        for region in response.get('items', []):
            regions.append({
                "name": region['name'],
                "display_name": region.get('description', region['name']),
                "availability_zones": [zone.split('/')[-1] for zone in region.get('zones', [])],
                "services": ["gke", "compute", "storage"]
            })
        
        return regions
        
    except Exception as e:
        logger.error(f"Failed to get GCP regions: {e}")
        return []


def _format_provider_response(provider: CloudProvider) -> CloudProviderResponse:
    """Format cloud provider object as response model."""
    
    return CloudProviderResponse(
        id=provider.id,
        name=provider.name,
        provider_type=provider.provider_type,
        description=provider.description,
        regions=provider.regions or [],
        status=provider.status,
        tags=provider.tags or {},
        created_at=provider.created_at,
        updated_at=provider.updated_at,
        last_validated=provider.last_validated
    ) 