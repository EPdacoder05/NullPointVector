"""
Shared security configuration for all guards.
"""

import os
from pathlib import Path
from typing import Dict, Any
import yaml
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class SecurityConfig:
    """Security configuration manager for all guards."""
    
    def __init__(self, config_path: str = "config/security.yaml"):
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.fernet = None
        self._load_config()
        self._setup_encryption()
        
    def _load_config(self):
        """Load security configuration from YAML file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.config = yaml.safe_load(f)
            else:
                self._create_default_config()
        except Exception as e:
            print(f"Error loading security config: {e}")
            self._create_default_config()
            
    def _create_default_config(self):
        """Create default security configuration."""
        self.config = {
            'encryption': {
                'enabled': True,
                'key_rotation_days': 30
            },
            'rate_limiting': {
                'enabled': True,
                'requests_per_minute': 60,
                'burst_limit': 10
            },
            'input_validation': {
                'enabled': True,
                'max_message_length': 10000,
                'allowed_characters': 'a-zA-Z0-9\\s\\.,!?@#$%^&*()_+-=[]{}|;:"\'<>/'
            },
            'audit_logging': {
                'enabled': True,
                'log_file': 'logs/security.log',
                'max_log_size_mb': 100,
                'backup_count': 5
            },
            'access_control': {
                'enabled': True,
                'allowed_ips': [],
                'blocked_ips': []
            },
            'guards': {
                'phishguard': {
                    'enabled': True,
                    'max_emails_per_minute': 100
                },
                'smishguard': {
                    'enabled': True,
                    'max_sms_per_minute': 50
                },
                'vishguard': {
                    'enabled': True,
                    'max_calls_per_minute': 20
                }
            }
        }
        self._save_config()
        
    def _save_config(self):
        """Save security configuration to YAML file."""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
        except Exception as e:
            print(f"Error saving security config: {e}")
            
    def _setup_encryption(self):
        """Set up encryption using Fernet."""
        try:
            key = os.getenv('ENCRYPTION_KEY')
            if not key:
                key = Fernet.generate_key()
                print(f"Generated new encryption key: {key.decode()}")
            self.fernet = Fernet(key)
        except Exception as e:
            print(f"Error setting up encryption: {e}")
            
    def encrypt_data(self, data: str) -> bytes:
        """Encrypt data using Fernet.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data
        """
        if not self.fernet:
            raise ValueError("Encryption not initialized")
        return self.fernet.encrypt(data.encode())
        
    def decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt data using Fernet.
        
        Args:
            encrypted_data: Data to decrypt
            
        Returns:
            Decrypted data
        """
        if not self.fernet:
            raise ValueError("Encryption not initialized")
        return self.fernet.decrypt(encrypted_data).decode()
        
    def get_rate_limit_config(self) -> Dict[str, Any]:
        """Get rate limiting configuration.
        
        Returns:
            Rate limiting configuration
        """
        return self.config.get('rate_limiting', {})
        
    def get_input_validation_config(self) -> Dict[str, Any]:
        """Get input validation configuration.
        
        Returns:
            Input validation configuration
        """
        return self.config.get('input_validation', {})
        
    def get_audit_logging_config(self) -> Dict[str, Any]:
        """Get audit logging configuration.
        
        Returns:
            Audit logging configuration
        """
        return self.config.get('audit_logging', {})
        
    def get_access_control_config(self) -> Dict[str, Any]:
        """Get access control configuration.
        
        Returns:
            Access control configuration
        """
        return self.config.get('access_control', {})
        
    def get_guard_config(self, guard_name: str) -> Dict[str, Any]:
        """Get configuration for a specific guard.
        
        Args:
            guard_name: Name of the guard (phishguard, smishguard, vishguard)
            
        Returns:
            Guard configuration
        """
        return self.config.get('guards', {}).get(guard_name.lower(), {})
        
    def update_config(self, section: str, key: str, value: Any):
        """Update security configuration.
        
        Args:
            section: Configuration section
            key: Configuration key
            value: New value
        """
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        self._save_config()
        
    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a security feature is enabled.
        
        Args:
            feature: Feature name
            
        Returns:
            True if enabled, False otherwise
        """
        section = feature.split('.')[0]
        key = feature.split('.')[1]
        return self.config.get(section, {}).get(key, False)
        
    def is_guard_enabled(self, guard_name: str) -> bool:
        """Check if a guard is enabled.
        
        Args:
            guard_name: Name of the guard
            
        Returns:
            True if enabled, False otherwise
        """
        return self.get_guard_config(guard_name).get('enabled', False)

# Create global security config instance
security_config = SecurityConfig() 