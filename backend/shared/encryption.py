"""
Shared encryption utilities for KubeNexus backend services.
Provides encryption/decryption for sensitive data like kubeconfigs and cloud credentials.
"""

import logging
import base64
import secrets
from typing import Optional, Union, Dict, Any
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

from .config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class EncryptionError(Exception):
    """Custom encryption error."""
    pass


class FernetEncryption:
    """Fernet-based encryption for general data."""
    
    def __init__(self, key: Optional[str] = None):
        """Initialize with encryption key."""
        if key is None:
            key = settings.kubeconfig_encryption_key
        
        # Ensure key is proper length for Fernet
        self.fernet = Fernet(self._derive_key(key))
    
    @staticmethod
    def _derive_key(password: str) -> bytes:
        """Derive a Fernet key from password."""
        # Use a fixed salt for consistency (in production, consider storing salt)
        salt = b"kubenexus_salt_1234567890123456"  # 32 bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, data: Union[str, bytes]) -> str:
        """Encrypt data and return base64 encoded string."""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            encrypted_data = self.fernet.encrypt(data)
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt data: {e}")
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt base64 encoded encrypted data."""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt data: {e}")
    
    def encrypt_json(self, data: Dict[str, Any]) -> str:
        """Encrypt JSON data."""
        try:
            json_string = json.dumps(data, sort_keys=True)
            return self.encrypt(json_string)
        except Exception as e:
            logger.error(f"JSON encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt JSON data: {e}")
    
    def decrypt_json(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt JSON data."""
        try:
            json_string = self.decrypt(encrypted_data)
            return json.loads(json_string)
        except Exception as e:
            logger.error(f"JSON decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt JSON data: {e}")


class AESEncryption:
    """AES-GCM encryption for high-security data."""
    
    def __init__(self, key: Optional[str] = None):
        """Initialize with encryption key."""
        if key is None:
            key = settings.cloud_provider_encryption_key
        
        # Derive 256-bit key from password
        self.key = self._derive_key(key)
    
    @staticmethod
    def _derive_key(password: str) -> bytes:
        """Derive AES key from password."""
        salt = b"kubenexus_aes_salt_567890123456"  # 32 bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt(self, data: Union[str, bytes]) -> str:
        """Encrypt data using AES-GCM."""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Generate random IV
            iv = secrets.token_bytes(12)  # 96-bit IV for GCM
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt data
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Combine IV + ciphertext + tag
            encrypted_data = iv + ciphertext + encryptor.tag
            
            # Return base64 encoded
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"AES encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt data: {e}")
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt AES-GCM encrypted data."""
        try:
            # Decode from base64
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            
            # Extract components
            iv = encrypted_bytes[:12]  # First 12 bytes
            tag = encrypted_bytes[-16:]  # Last 16 bytes
            ciphertext = encrypted_bytes[12:-16]  # Everything in between
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            logger.error(f"AES decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt data: {e}")
    
    def encrypt_json(self, data: Dict[str, Any]) -> str:
        """Encrypt JSON data using AES."""
        try:
            json_string = json.dumps(data, sort_keys=True)
            return self.encrypt(json_string)
        except Exception as e:
            logger.error(f"AES JSON encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt JSON data: {e}")
    
    def decrypt_json(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt JSON data using AES."""
        try:
            json_string = self.decrypt(encrypted_data)
            return json.loads(json_string)
        except Exception as e:
            logger.error(f"AES JSON decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt JSON data: {e}")


class KubeconfigManager:
    """Specialized manager for kubeconfig encryption."""
    
    def __init__(self):
        self.encryption = FernetEncryption(settings.kubeconfig_encryption_key)
    
    def encrypt_kubeconfig(self, kubeconfig: Union[str, Dict[str, Any]]) -> str:
        """Encrypt kubeconfig data."""
        try:
            if isinstance(kubeconfig, dict):
                # Convert dict to YAML string
                import yaml
                kubeconfig_str = yaml.dump(kubeconfig, default_flow_style=False)
            else:
                kubeconfig_str = kubeconfig
            
            return self.encryption.encrypt(kubeconfig_str)
            
        except Exception as e:
            logger.error(f"Kubeconfig encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt kubeconfig: {e}")
    
    def decrypt_kubeconfig(self, encrypted_kubeconfig: str) -> str:
        """Decrypt kubeconfig data."""
        try:
            return self.encryption.decrypt(encrypted_kubeconfig)
        except Exception as e:
            logger.error(f"Kubeconfig decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt kubeconfig: {e}")
    
    def decrypt_kubeconfig_to_dict(self, encrypted_kubeconfig: str) -> Dict[str, Any]:
        """Decrypt kubeconfig and return as dictionary."""
        try:
            import yaml
            kubeconfig_str = self.decrypt_kubeconfig(encrypted_kubeconfig)
            return yaml.safe_load(kubeconfig_str)
        except Exception as e:
            logger.error(f"Kubeconfig decryption to dict failed: {e}")
            raise EncryptionError(f"Failed to decrypt kubeconfig to dict: {e}")


class CloudProviderConfigManager:
    """Specialized manager for cloud provider configuration encryption."""
    
    def __init__(self):
        self.encryption = AESEncryption(settings.cloud_provider_encryption_key)
    
    def encrypt_aws_config(self, config: Dict[str, Any]) -> str:
        """Encrypt AWS configuration."""
        try:
            # Validate required AWS fields
            required_fields = ['access_key_id', 'secret_access_key', 'region']
            missing_fields = [field for field in required_fields if field not in config]
            if missing_fields:
                raise EncryptionError(f"Missing required AWS fields: {missing_fields}")
            
            return self.encryption.encrypt_json(config)
            
        except Exception as e:
            logger.error(f"AWS config encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt AWS config: {e}")
    
    def encrypt_azure_config(self, config: Dict[str, Any]) -> str:
        """Encrypt Azure configuration."""
        try:
            # Validate required Azure fields
            required_fields = ['client_id', 'client_secret', 'tenant_id', 'subscription_id']
            missing_fields = [field for field in required_fields if field not in config]
            if missing_fields:
                raise EncryptionError(f"Missing required Azure fields: {missing_fields}")
            
            return self.encryption.encrypt_json(config)
            
        except Exception as e:
            logger.error(f"Azure config encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt Azure config: {e}")
    
    def encrypt_gcp_config(self, config: Dict[str, Any]) -> str:
        """Encrypt GCP configuration."""
        try:
            # Validate required GCP fields
            required_fields = ['project_id']
            missing_fields = [field for field in required_fields if field not in config]
            if missing_fields:
                raise EncryptionError(f"Missing required GCP fields: {missing_fields}")
            
            return self.encryption.encrypt_json(config)
            
        except Exception as e:
            logger.error(f"GCP config encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt GCP config: {e}")
    
    def decrypt_cloud_config(self, encrypted_config: str) -> Dict[str, Any]:
        """Decrypt cloud provider configuration."""
        try:
            return self.encryption.decrypt_json(encrypted_config)
        except Exception as e:
            logger.error(f"Cloud config decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt cloud config: {e}")


class CloudCredentialsManager:
    """Manager for cloud provider credentials encryption."""
    
    def __init__(self):
        self.cloud_config_manager = CloudProviderConfigManager()
    
    @staticmethod
    def encrypt_credentials(provider_type: str, credentials: Dict[str, Any]) -> str:
        """Encrypt cloud provider credentials."""
        manager = CloudProviderConfigManager()
        
        if provider_type == 'aws':
            return manager.encrypt_aws_config(credentials)
        elif provider_type == 'azure':
            return manager.encrypt_azure_config(credentials)
        elif provider_type == 'gcp':
            return manager.encrypt_gcp_config(credentials)
        else:
            raise EncryptionError(f"Unsupported provider type: {provider_type}")
    
    @staticmethod
    def decrypt_credentials(encrypted_credentials: str) -> Dict[str, Any]:
        """Decrypt cloud provider credentials."""
        manager = CloudProviderConfigManager()
        return manager.decrypt_cloud_config(encrypted_credentials)


class SecretManager:
    """Manager for general secret encryption/decryption."""
    
    def __init__(self):
        self.fernet_encryption = FernetEncryption()
        self.aes_encryption = AESEncryption()
    
    def encrypt_secret(self, secret: str, use_aes: bool = False) -> str:
        """Encrypt a secret string."""
        try:
            if use_aes:
                return self.aes_encryption.encrypt(secret)
            else:
                return self.fernet_encryption.encrypt(secret)
        except Exception as e:
            logger.error(f"Secret encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt secret: {e}")
    
    def decrypt_secret(self, encrypted_secret: str, use_aes: bool = False) -> str:
        """Decrypt a secret string."""
        try:
            if use_aes:
                return self.aes_encryption.decrypt(encrypted_secret)
            else:
                return self.fernet_encryption.decrypt(encrypted_secret)
        except Exception as e:
            logger.error(f"Secret decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt secret: {e}")
    
    def encrypt_password(self, password: str) -> str:
        """Encrypt a password using AES (more secure)."""
        return self.encrypt_secret(password, use_aes=True)
    
    def decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt a password."""
        return self.decrypt_secret(encrypted_password, use_aes=True)


# Global instances
kubeconfig_manager = KubeconfigManager()
cloud_config_manager = CloudProviderConfigManager()
secret_manager = SecretManager()


def generate_encryption_key() -> str:
    """Generate a new encryption key for configuration."""
    return Fernet.generate_key().decode()


def validate_encryption_key(key: str) -> bool:
    """Validate if a key is suitable for encryption."""
    try:
        # Try to create a Fernet instance
        FernetEncryption(key)
        return True
    except Exception:
        return False


def test_encryption_decryption() -> bool:
    """Test encryption and decryption functionality."""
    try:
        test_data = "KubeNexus test encryption data"
        
        # Test Fernet encryption
        fernet_enc = FernetEncryption()
        encrypted = fernet_enc.encrypt(test_data)
        decrypted = fernet_enc.decrypt(encrypted)
        
        if decrypted != test_data:
            return False
        
        # Test AES encryption
        aes_enc = AESEncryption()
        encrypted_aes = aes_enc.encrypt(test_data)
        decrypted_aes = aes_enc.decrypt(encrypted_aes)
        
        if decrypted_aes != test_data:
            return False
        
        # Test JSON encryption
        test_json = {"test": "data", "number": 123}
        encrypted_json = fernet_enc.encrypt_json(test_json)
        decrypted_json = fernet_enc.decrypt_json(encrypted_json)
        
        if decrypted_json != test_json:
            return False
        
        logger.info("Encryption/decryption test passed")
        return True
        
    except Exception as e:
        logger.error(f"Encryption/decryption test failed: {e}")
        return False


# Utility functions for database field encryption
def encrypt_field(value: str, use_aes: bool = False) -> Optional[str]:
    """Encrypt a database field value."""
    if not value:
        return None
    
    try:
        return secret_manager.encrypt_secret(value, use_aes=use_aes)
    except Exception as e:
        logger.error(f"Field encryption failed: {e}")
        return None


def decrypt_field(encrypted_value: str, use_aes: bool = False) -> Optional[str]:
    """Decrypt a database field value."""
    if not encrypted_value:
        return None
    
    try:
        return secret_manager.decrypt_secret(encrypted_value, use_aes=use_aes)
    except Exception as e:
        logger.error(f"Field decryption failed: {e}")
        return None


# Environment variable encryption helpers
def encrypt_env_var(var_name: str, value: str) -> str:
    """Encrypt an environment variable value."""
    return f"ENCRYPTED:{secret_manager.encrypt_secret(value)}"


def decrypt_env_var(encrypted_value: str) -> str:
    """Decrypt an environment variable value."""
    if encrypted_value.startswith("ENCRYPTED:"):
        encrypted_part = encrypted_value[10:]  # Remove "ENCRYPTED:" prefix
        return secret_manager.decrypt_secret(encrypted_part)
    return encrypted_value  # Return as-is if not encrypted


def get_encrypted_env_var(var_name: str, default: str = None) -> str:
    """Get and decrypt an environment variable."""
    value = os.getenv(var_name, default)
    if value:
        return decrypt_env_var(value)
    return value 