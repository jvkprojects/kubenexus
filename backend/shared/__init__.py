"""
KubeNexus Shared Utilities Module
Provides common utilities for all backend services.
"""

from .config import Settings, get_settings
from .database import (
    Base, 
    init_database, 
    close_database, 
    get_db, 
    get_async_db, 
    get_async_db_dependency,
    db_manager,
    check_database_health,
    wait_for_database
)
from .auth import (
    PasswordManager,
    TokenManager,
    SessionManager,
    AuthenticationError,
    AuthorizationError,
    get_current_user,
    get_current_active_user,
    require_permissions,
    require_permission,
    require_role,
    RateLimiter,
    LoginAttemptTracker,
    init_auth
)
from .encryption import (
    EncryptionError,
    FernetEncryption,
    AESEncryption,
    KubeconfigManager,
    CloudProviderConfigManager,
    CloudCredentialsManager,
    SecretManager,
    kubeconfig_manager,
    cloud_config_manager,
    secret_manager,
    generate_encryption_key,
    validate_encryption_key,
    test_encryption_decryption,
    encrypt_field,
    decrypt_field
)
from .log_utils import (
    setup_logging,
    get_logger,
    log_context,
    log_function_call,
    log_async_function_call,
    performance_log,
    audit_logger,
    security_logger,
    init_logging
)
from .models import (
    User,
    Organization,
    Role,
    Permission,
    UserRole,
    RolePermission,
    KubernetesCluster,
    CloudProvider,
    AuditLog,
    ApplicationSetting,
    UserPreference,
    Plugin,
    ProblemApplication,
    ResolutionSuggestion,
    UserSession,
    MetricsCache,
    TimestampMixin,
    MODELS
)

__version__ = "1.0.0"
__author__ = "KubeNexus Team"
__description__ = "Shared utilities for KubeNexus backend services"

# Module level initialization functions
async def init_shared_services():
    """Initialize all shared services."""
    # Initialize database
    init_database()
    
    # Initialize authentication
    init_auth()
    
    # Test encryption
    if not test_encryption_decryption():
        raise RuntimeError("Encryption test failed")

async def cleanup_shared_services():
    """Cleanup shared services."""
    # Close database connections
    await close_database()

# Export key components
__all__ = [
    # Configuration
    'Settings',
    'get_settings',
    
    # Database
    'Base',
    'init_database',
    'close_database',
    'get_db',
    'get_async_db',
    'get_async_db_dependency',
    'db_manager',
    'check_database_health',
    'wait_for_database',
    
    # Authentication
    'PasswordManager',
    'TokenManager',
    'SessionManager',
    'AuthenticationError',
    'AuthorizationError',
    'get_current_user',
    'get_current_active_user',
    'require_permissions',
    'require_permission',
    'require_role',
    'RateLimiter',
    'LoginAttemptTracker',
    'init_auth',
    
    # Encryption
    'EncryptionError',
    'FernetEncryption',
    'AESEncryption',
    'KubeconfigManager',
    'CloudProviderConfigManager',
    'CloudCredentialsManager',
    'SecretManager',
    'kubeconfig_manager',
    'cloud_config_manager',
    'secret_manager',
    'generate_encryption_key',
    'validate_encryption_key',
    'test_encryption_decryption',
    'encrypt_field',
    'decrypt_field',
    
    # Logging
    'setup_logging',
    'get_logger',
    'log_context',
    'log_function_call',
    'log_async_function_call',
    'performance_log',
    'audit_logger',
    'security_logger',
    'init_logging',
    
    # Models
    'User',
    'Organization',
    'Role',
    'Permission',
    'UserRole',
    'RolePermission',
    'KubernetesCluster',
    'CloudProvider',
    'AuditLog',
    'ApplicationSetting',
    'UserPreference',
    'Plugin',
    'ProblemApplication',
    'ResolutionSuggestion',
    'UserSession',
    'MetricsCache',
    'TimestampMixin',
    'MODELS',
    
    # Initialization
    'init_shared_services',
    'cleanup_shared_services',
] 