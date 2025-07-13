"""
Shared database models for KubeNexus backend services.
SQLAlchemy models matching the database schema.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import Column, String, Text, Integer, Boolean, DateTime, DECIMAL, ForeignKey, Index, JSON
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB, ENUM
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func
from sqlalchemy.ext.hybrid import hybrid_property

from .database import Base

# Create ENUM types
ClusterTypeEnum = ENUM('on-premise', 'eks', 'gke', 'aks', name='cluster_type')
ClusterStatusEnum = ENUM('connected', 'disconnected', 'error', 'pending', name='cluster_status')
UserStatusEnum = ENUM('active', 'inactive', 'suspended', name='user_status')
ProblemSeverityEnum = ENUM('critical', 'high', 'medium', 'low', name='problem_severity')
AuditActionEnum = ENUM('create', 'read', 'update', 'delete', 'login', 'logout', 'access_denied', name='audit_action')
CloudProviderTypeEnum = ENUM('aws', 'azure', 'gcp', name='cloud_provider_type')
CloudProviderStatusEnum = ENUM('active', 'inactive', 'error', 'validating', name='cloud_provider_status')


class TimestampMixin:
    """Mixin for created_at and updated_at timestamps."""
    
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)


class User(Base, TimestampMixin):
    """User model."""
    
    __tablename__ = 'users'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=True)  # NULL for SSO/LDAP users
    sso_id = Column(String(255), nullable=True, index=True)
    ldap_dn = Column(String(500), nullable=True)
    ad_dn = Column(String(500), nullable=True)
    first_name = Column(String(255), nullable=True)
    last_name = Column(String(255), nullable=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=True, index=True)
    status = Column(UserStatusEnum, default='active', nullable=False, index=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    organization = relationship("Organization", back_populates="users")
    user_roles = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    created_clusters = relationship("KubernetesCluster", back_populates="creator")
    user_sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    user_preferences = relationship("UserPreference", back_populates="user", cascade="all, delete-orphan")
    resolved_problems = relationship("ProblemApplication", foreign_keys="ProblemApplication.resolved_by")
    
    @hybrid_property
    def full_name(self):
        """Get user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"


class Organization(Base, TimestampMixin):
    """Organization model."""
    
    __tablename__ = 'organizations'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(50), default='active', nullable=False, index=True)
    contact_email = Column(String(255), nullable=True)
    
    # Relationships
    users = relationship("User", back_populates="organization")
    
    def __repr__(self):
        return f"<Organization(id={self.id}, name='{self.name}')>"


class Role(Base, TimestampMixin):
    """Role model."""
    
    __tablename__ = 'roles'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_system_role = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    user_roles = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")
    role_permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Role(id={self.id}, name='{self.name}')>"


class Permission(Base):
    """Permission model."""
    
    __tablename__ = 'permissions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    resource_type = Column(String(100), nullable=True, index=True)
    action = Column(String(50), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    
    # Relationships
    role_permissions = relationship("RolePermission", back_populates="permission", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Permission(id={self.id}, name='{self.name}')>"


class UserRole(Base):
    """User-Role association model."""
    
    __tablename__ = 'user_roles'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey('roles.id', ondelete='CASCADE'), nullable=False, index=True)
    cluster_id = Column(UUID(as_uuid=True), ForeignKey('kubernetes_clusters.id', ondelete='CASCADE'), nullable=True, index=True)
    namespace = Column(String(255), nullable=True)
    granted_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    granted_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    
    # Relationships
    user = relationship("User", back_populates="user_roles", foreign_keys=[user_id])
    role = relationship("Role", back_populates="user_roles")
    cluster = relationship("KubernetesCluster", foreign_keys=[cluster_id])
    granter = relationship("User", foreign_keys=[granted_by])
    
    __table_args__ = (
        Index('ix_user_roles_unique', 'user_id', 'role_id', 'cluster_id', 'namespace', unique=True),
    )
    
    def __repr__(self):
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id})>"


class RolePermission(Base):
    """Role-Permission association model."""
    
    __tablename__ = 'role_permissions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    role_id = Column(UUID(as_uuid=True), ForeignKey('roles.id', ondelete='CASCADE'), nullable=False, index=True)
    permission_id = Column(UUID(as_uuid=True), ForeignKey('permissions.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Relationships
    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")
    
    __table_args__ = (
        Index('ix_role_permissions_unique', 'role_id', 'permission_id', unique=True),
    )
    
    def __repr__(self):
        return f"<RolePermission(role_id={self.role_id}, permission_id={self.permission_id})>"


class KubernetesCluster(Base, TimestampMixin):
    """Kubernetes cluster model."""
    
    __tablename__ = 'kubernetes_clusters'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False, index=True)
    type = Column(ClusterTypeEnum, nullable=False, index=True)
    description = Column(Text, nullable=True)
    kubeconfig = Column(Text, nullable=True)  # Encrypted kubeconfig for on-premise
    cloud_provider_config = Column(JSONB, nullable=True)  # Encrypted cloud provider config
    api_endpoint = Column(String(500), nullable=True)
    status = Column(ClusterStatusEnum, default='pending', nullable=False, index=True)
    version = Column(String(50), nullable=True)
    node_count = Column(Integer, default=0, nullable=False)
    last_health_check = Column(DateTime(timezone=True), nullable=True)
    health_check_error = Column(Text, nullable=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False, index=True)
    cloud_provider_id = Column(UUID(as_uuid=True), ForeignKey('cloud_providers.id'), nullable=True, index=True)
    
    # Relationships
    creator = relationship("User", back_populates="created_clusters", foreign_keys=[created_by])
    cloud_provider = relationship("CloudProvider", back_populates="clusters")
    user_roles = relationship("UserRole", back_populates="cluster", foreign_keys="UserRole.cluster_id")
    audit_logs = relationship("AuditLog", back_populates="cluster")
    problem_applications = relationship("ProblemApplication", back_populates="cluster", cascade="all, delete-orphan")
    metrics_cache = relationship("MetricsCache", back_populates="cluster", cascade="all, delete-orphan")
    
    @hybrid_property
    def is_healthy(self):
        """Check if cluster is healthy."""
        return self.status == 'connected'
    
    def __repr__(self):
        return f"<KubernetesCluster(id={self.id}, name='{self.name}', type='{self.type}')>"


class AuditLog(Base):
    """Audit log model."""
    
    __tablename__ = 'audit_logs'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    action = Column(AuditActionEnum, nullable=False, index=True)
    resource_type = Column(String(100), nullable=True, index=True)
    resource_name = Column(String(255), nullable=True)
    resource_id = Column(UUID(as_uuid=True), nullable=True)
    namespace = Column(String(255), nullable=True)
    cluster_id = Column(UUID(as_uuid=True), ForeignKey('kubernetes_clusters.id', ondelete='SET NULL'), nullable=True, index=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    request_data = Column(JSONB, nullable=True)
    response_data = Column(JSONB, nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=func.now(), nullable=False, index=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    cluster = relationship("KubernetesCluster", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, action='{self.action}', timestamp={self.timestamp})>"


class ApplicationSetting(Base):
    """Application settings model."""
    
    __tablename__ = 'application_settings'
    
    key = Column(String(255), primary_key=True)
    value = Column(JSONB, nullable=False)
    description = Column(Text, nullable=True)
    is_encrypted = Column(Boolean, default=False, nullable=False)
    updated_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    updater = relationship("User", foreign_keys=[updated_by])
    
    def __repr__(self):
        return f"<ApplicationSetting(key='{self.key}')>"


class UserPreference(Base):
    """User preferences model."""
    
    __tablename__ = 'user_preferences'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    key = Column(String(255), nullable=False)
    value = Column(JSONB, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="user_preferences")
    
    __table_args__ = (
        Index('ix_user_preferences_unique', 'user_id', 'key', unique=True),
    )
    
    def __repr__(self):
        return f"<UserPreference(user_id={self.user_id}, key='{self.key}')>"


class Plugin(Base, TimestampMixin):
    """Plugin model."""
    
    __tablename__ = 'plugins'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False, index=True)
    version = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    configuration = Column(JSONB, nullable=True)
    status = Column(String(50), default='disabled', nullable=False)
    installed_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    installed_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    
    # Relationships
    installer = relationship("User", foreign_keys=[installed_by])
    
    def __repr__(self):
        return f"<Plugin(id={self.id}, name='{self.name}', version='{self.version}')>"


class ProblemApplication(Base):
    """Problem application model for SRE agent."""
    
    __tablename__ = 'problem_applications'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id = Column(UUID(as_uuid=True), ForeignKey('kubernetes_clusters.id', ondelete='CASCADE'), nullable=False, index=True)
    namespace = Column(String(255), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False, index=True)
    resource_name = Column(String(255), nullable=False)
    problem_type = Column(String(100), nullable=False, index=True)
    problem_description = Column(Text, nullable=False)
    severity = Column(ProblemSeverityEnum, nullable=False, index=True)
    detection_data = Column(JSONB, nullable=True)
    root_cause = Column(Text, nullable=True)
    auto_resolved = Column(Boolean, default=False, nullable=False)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=True)
    detected_at = Column(DateTime(timezone=True), default=func.now(), nullable=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_occurrence = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    occurrence_count = Column(Integer, default=1, nullable=False)
    
    # Relationships
    cluster = relationship("KubernetesCluster", back_populates="problem_applications")
    resolver = relationship("User", foreign_keys=[resolved_by])
    resolution_suggestions = relationship("ResolutionSuggestion", back_populates="problem", cascade="all, delete-orphan")
    
    @hybrid_property
    def is_resolved(self):
        """Check if problem is resolved."""
        return self.resolved_at is not None
    
    @hybrid_property
    def age_hours(self):
        """Get problem age in hours."""
        if self.resolved_at:
            end_time = self.resolved_at
        else:
            end_time = datetime.now(timezone.utc)
        return (end_time - self.detected_at).total_seconds() / 3600
    
    def __repr__(self):
        return f"<ProblemApplication(id={self.id}, type='{self.problem_type}', severity='{self.severity}')>"


class ResolutionSuggestion(Base):
    """Resolution suggestion model for SRE agent."""
    
    __tablename__ = 'resolution_suggestions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    problem_id = Column(UUID(as_uuid=True), ForeignKey('problem_applications.id', ondelete='CASCADE'), nullable=False, index=True)
    suggestion_text = Column(Text, nullable=False)
    command_example = Column(Text, nullable=True)
    documentation_link = Column(String(500), nullable=True)
    confidence_score = Column(DECIMAL(3, 2), nullable=True)
    priority = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    
    # Relationships
    problem = relationship("ProblemApplication", back_populates="resolution_suggestions")
    
    def __repr__(self):
        return f"<ResolutionSuggestion(id={self.id}, problem_id={self.problem_id})>"


class UserSession(Base):
    """User session model."""
    
    __tablename__ = 'user_sessions'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    refresh_token = Column(String(255), unique=True, nullable=True)
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    last_accessed_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="user_sessions")
    
    @hybrid_property
    def is_expired(self):
        """Check if session is expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def __repr__(self):
        return f"<UserSession(id={self.id}, user_id={self.user_id})>"


class MetricsCache(Base):
    """Metrics cache model."""
    
    __tablename__ = 'metrics_cache'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cluster_id = Column(UUID(as_uuid=True), ForeignKey('kubernetes_clusters.id', ondelete='CASCADE'), nullable=False, index=True)
    metric_type = Column(String(100), nullable=False, index=True)
    metric_data = Column(JSONB, nullable=False)
    namespace = Column(String(255), nullable=True)
    cached_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # Relationships
    cluster = relationship("KubernetesCluster", back_populates="metrics_cache")
    
    __table_args__ = (
        Index('ix_metrics_cache_unique', 'cluster_id', 'metric_type', 'namespace', unique=True),
    )
    
    @hybrid_property
    def is_expired(self):
        """Check if cached metrics are expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def __repr__(self):
        return f"<MetricsCache(cluster_id={self.cluster_id}, type='{self.metric_type}')>"


class CloudProvider(Base, TimestampMixin):
    """Cloud provider model."""
    
    __tablename__ = 'cloud_providers'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False, index=True)
    provider_type = Column(CloudProviderTypeEnum, nullable=False, index=True)
    description = Column(Text, nullable=True)
    credentials_encrypted = Column(Text, nullable=False)  # Encrypted credentials
    regions = Column(JSONB, nullable=True)  # List of available regions
    status = Column(CloudProviderStatusEnum, default='active', nullable=False, index=True)
    tags = Column(JSONB, nullable=True)  # Key-value tags
    last_validated = Column(DateTime(timezone=True), nullable=True)
    validation_error = Column(Text, nullable=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False, index=True)
    
    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    clusters = relationship("KubernetesCluster", back_populates="cloud_provider")
    
    @hybrid_property
    def is_healthy(self):
        """Check if cloud provider is healthy."""
        return self.status == 'active'
    
    def __repr__(self):
        return f"<CloudProvider(id={self.id}, name='{self.name}', type='{self.provider_type}')>"


# Additional indexes for performance
Index('ix_audit_logs_composite', AuditLog.user_id, AuditLog.action, AuditLog.timestamp)
Index('ix_problem_applications_composite', ProblemApplication.cluster_id, ProblemApplication.severity, ProblemApplication.detected_at)
Index('ix_user_roles_composite', UserRole.user_id, UserRole.cluster_id, UserRole.namespace)


# Model registry for easier access
MODELS = {
    'User': User,
    'Organization': Organization,
    'Role': Role,
    'Permission': Permission,
    'UserRole': UserRole,
    'RolePermission': RolePermission,
    'KubernetesCluster': KubernetesCluster,
    'AuditLog': AuditLog,
    'ApplicationSetting': ApplicationSetting,
    'UserPreference': UserPreference,
    'Plugin': Plugin,
    'ProblemApplication': ProblemApplication,
    'ResolutionSuggestion': ResolutionSuggestion,
    'UserSession': UserSession,
    'MetricsCache': MetricsCache,
    'CloudProvider': CloudProvider,
} 