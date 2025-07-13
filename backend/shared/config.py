"""
Shared configuration module for KubeNexus backend services.
Provides centralized configuration management using Pydantic Settings.
"""

import os
from typing import List, Optional
from pydantic import validator, AnyHttpUrl
from pydantic_settings import BaseSettings


class DatabaseSettings(BaseSettings):
    """Database configuration settings."""
    
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "kubenexus"
    postgres_user: str = "kubenexus_user"
    postgres_password: str = ""
    database_url: Optional[str] = None
    
    # Database pool settings
    db_pool_size: int = 20
    db_max_overflow: int = 0
    db_pool_timeout: int = 30
    db_pool_recycle: int = 1800
    
    @validator("database_url", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: dict) -> str:
        if isinstance(v, str):
            return v
        return (
            f"postgresql://{values.get('postgres_user')}:"
            f"{values.get('postgres_password')}@"
            f"{values.get('postgres_host')}:"
            f"{values.get('postgres_port')}/"
            f"{values.get('postgres_db')}"
        )


class RedisSettings(BaseSettings):
    """Redis configuration settings."""
    
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: Optional[str] = None
    redis_db: int = 0
    redis_url: Optional[str] = None
    
    # Redis pool settings
    redis_max_connections: int = 100
    redis_socket_timeout: int = 5
    redis_socket_connect_timeout: int = 5
    redis_health_check_interval: int = 30
    
    @validator("redis_url", pre=True)
    def assemble_redis_connection(cls, v: Optional[str], values: dict) -> str:
        if isinstance(v, str):
            return v
        
        auth = ""
        if values.get("redis_password"):
            auth = f":{values.get('redis_password')}@"
        
        return (
            f"redis://{auth}{values.get('redis_host')}:"
            f"{values.get('redis_port')}/{values.get('redis_db')}"
        )


class SecuritySettings(BaseSettings):
    """Security and authentication settings."""
    
    # JWT settings
    jwt_secret: str = "super_secret_jwt_key_change_in_production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    jwt_refresh_expire_days: int = 7
    
    # Encryption keys
    kubeconfig_encryption_key: str = "32_char_encryption_key_here_123456"
    cloud_provider_encryption_key: str = "another_32_char_key_for_cloud_123"
    
    # Password settings
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_special: bool = True
    
    # Session settings
    session_timeout: int = 3600  # 1 hour
    max_login_attempts: int = 5
    lockout_duration: int = 900  # 15 minutes
    
    # Rate limiting
    rate_limit_per_minute: int = 100
    rate_limit_burst: int = 20
    
    @validator("kubeconfig_encryption_key", "cloud_provider_encryption_key")
    def validate_encryption_key_length(cls, v):
        if len(v) < 32:
            raise ValueError("Encryption key must be at least 32 characters long")
        return v


class ServiceSettings(BaseSettings):
    """Service configuration settings."""
    
    # Service ports
    auth_service_port: int = 8000
    cluster_manager_service_port: int = 8001
    sre_agent_service_port: int = 8002
    audit_log_service_port: int = 8003
    metrics_service_port: int = 8004
    terminal_service_port: int = 8005
    api_gateway_port: int = 80
    
    # Service URLs (for inter-service communication)
    auth_service_url: str = "http://auth-service:8000"
    cluster_manager_service_url: str = "http://cluster-manager-service:8001"
    sre_agent_service_url: str = "http://sre-agent-service:8002"
    audit_log_service_url: str = "http://audit-log-service:8003"
    metrics_service_url: str = "http://metrics-service:8004"
    terminal_service_url: str = "http://terminal-service:8005"


class APISettings(BaseSettings):
    """API configuration settings."""
    
    api_v1_prefix: str = "/api/v1"
    backend_cors_origins: List[AnyHttpUrl] = [
        "http://localhost:3000",
        "http://localhost:80"
    ]
    
    # API limits
    max_upload_size: int = 10 * 1024 * 1024  # 10MB
    request_timeout: int = 300  # 5 minutes
    
    # Health check settings
    health_check_interval: int = 30
    health_check_timeout: int = 10
    
    @validator("backend_cors_origins", pre=True)
    def assemble_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.replace('[', '').replace(']', '').replace('"', '').split(',')]
        return v


class SRESettings(BaseSettings):
    """SRE Agent configuration settings."""
    
    sre_monitoring_enabled: bool = True
    sre_monitoring_interval_seconds: int = 60
    sre_anomaly_detection_threshold: float = 0.8
    sre_max_suggestions_per_problem: int = 5
    sre_problem_retention_days: int = 30
    sre_metrics_window_minutes: int = 15
    
    # ML model settings
    sre_model_retrain_hours: int = 24
    sre_confidence_threshold: float = 0.7
    sre_false_positive_threshold: float = 0.1


class LoggingSettings(BaseSettings):
    """Logging configuration settings."""
    
    log_level: str = "INFO"
    log_format: str = "json"  # json or text
    log_file: Optional[str] = None
    log_max_size: int = 100 * 1024 * 1024  # 100MB
    log_backup_count: int = 5
    
    # Structured logging settings
    log_service_name: Optional[str] = None
    log_service_version: str = "1.0.0"
    log_environment: str = "development"


class MonitoringSettings(BaseSettings):
    """Monitoring and observability settings."""
    
    enable_metrics: bool = True
    metrics_port: int = 9090
    metrics_path: str = "/metrics"
    
    enable_tracing: bool = True
    jaeger_endpoint: Optional[str] = None
    tracing_sample_rate: float = 0.1
    
    # Prometheus settings
    prometheus_multiproc_dir: Optional[str] = None


class CloudProviderSettings(BaseSettings):
    """Cloud provider configuration settings."""
    
    # AWS settings
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_default_region: str = "us-west-2"
    aws_session_token: Optional[str] = None
    
    # Google Cloud settings
    google_application_credentials: Optional[str] = None
    google_cloud_project: Optional[str] = None
    
    # Azure settings
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_subscription_id: Optional[str] = None


class LDAPSettings(BaseSettings):
    """LDAP configuration settings."""
    
    ldap_server: Optional[str] = None
    ldap_port: int = 389
    ldap_use_ssl: bool = False
    ldap_base_dn: Optional[str] = None
    ldap_user_dn: Optional[str] = None
    ldap_password: Optional[str] = None
    ldap_user_search: str = "(uid={username})"
    ldap_group_search: str = "(cn={group})"
    ldap_timeout: int = 10


class ActiveDirectorySettings(BaseSettings):
    """Active Directory configuration settings."""
    
    ad_server: Optional[str] = None
    ad_port: int = 389
    ad_use_ssl: bool = False
    ad_domain: Optional[str] = None
    ad_user: Optional[str] = None
    ad_password: Optional[str] = None
    ad_timeout: int = 10


class SSOSettings(BaseSettings):
    """SSO configuration settings."""
    
    sso_client_id: Optional[str] = None
    sso_client_secret: Optional[str] = None
    sso_discovery_url: Optional[str] = None
    sso_redirect_uri: str = "http://localhost:3000/auth/callback"
    sso_scopes: List[str] = ["openid", "profile", "email"]


class Settings(
    DatabaseSettings,
    RedisSettings,
    SecuritySettings,
    ServiceSettings,
    APISettings,
    SRESettings,
    LoggingSettings,
    MonitoringSettings,
    CloudProviderSettings,
    LDAPSettings,
    ActiveDirectorySettings,
    SSOSettings
):
    """Combined application settings."""
    
    # Application metadata
    app_name: str = "KubeNexus"
    app_version: str = "1.0.0"
    app_description: str = "Enterprise Kubernetes Control Plane"
    
    # Environment settings
    environment: str = "development"
    debug: bool = True
    testing: bool = False
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings instance."""
    return settings 