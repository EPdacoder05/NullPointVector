"""
Hardened Security Configuration Manager
Implements AES-256-GCM encryption, Argon2 hashing, and strict access controls.
"""

import os
import logging
import yaml
import base64
import secrets
from pathlib import Path
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

# Cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Hashing (requires passlib & bcrypt/argon2-cffi)
from passlib.hash import argon2

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecurityGuard")

# Load environment variables
load_dotenv()

class SecurityConfig:
    """
    Hardened security configuration manager.
    Handles AES-256-GCM encryption, secure config storage, and secret hashing.
    """
    
    def __init__(self, config_path: str = "config/security.yaml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.aesgcm: Optional[AESGCM] = None
        self.rotation_keys: List[AESGCM] = []
        
        self._setup_encryption()
        self._load_config()
        
    def _setup_encryption(self):
        """
        Initialize AES-256-GCM encryption.
        Strictly requires ENCRYPTION_KEY in environment.
        """
        try:
            # 1. Primary Key
            key_b64 = os.getenv('ENCRYPTION_KEY')
            if not key_b64:
                # INSECURE: Generating key on fly. Only allowed in DEV.
                if os.getenv('FLASK_ENV') == 'development':
                    logger.warning("⚠️  DEV MODE: Generating temporary encryption key. DATA WILL BE LOST ON RESTART.")
                    key = AESGCM.generate_key(bit_length=256)
                    logger.info(f"Generated Key (Save to .env): {base64.urlsafe_b64encode(key).decode()}")
                else:
                    raise ValueError("CRITICAL: ENCRYPTION_KEY missing in production environment.")
            else:
                key = base64.urlsafe_b64decode(key_b64)

            # Validate Key Length (AES-256 requires 32 bytes)
            if len(key) != 32:
                raise ValueError(f"Invalid key length: {len(key)} bytes. AES-256 requires 32 bytes.")

            self.aesgcm = AESGCM(key)

            # 2. Rotation Keys (Optional: for decrypting old data)
            rotation_keys_env = os.getenv('ROTATION_KEYS', '')
            if rotation_keys_env:
                for k in rotation_keys_env.split(','):
                    if k.strip():
                        r_key = base64.urlsafe_b64decode(k.strip())
                        self.rotation_keys.append(AESGCM(r_key))

        except Exception as e:
            logger.critical(f"Failed to initialize encryption: {e}")
            raise

    def _load_config(self):
        """Load security configuration with permission checks."""
        try:
            if self.config_path.exists():
                # Check permissions (Unix only)
                if os.name == 'posix':
                    stat = self.config_path.stat()
                    # Ensure file is 600 (rw-------)
                    if stat.st_mode & 0o777 != 0o600:
                        logger.warning(f"Fixing insecure permissions on {self.config_path}")
                        os.chmod(self.config_path, 0o600)

                with open(self.config_path, 'r') as f:
                    self.config = yaml.safe_load(f) or {}
            else:
                self._create_default_config()
        except Exception as e:
            logger.error(f"Error loading security config: {e}")
            self._create_default_config()

    def _create_default_config(self):
        """Create secure default configuration."""
        self.config = {
            'encryption': {
                'enabled': True,
                'algorithm': 'AES-256-GCM',
                'key_rotation_days': 90
            },
            'rate_limiting': {
                'enabled': True,
                'requests_per_minute': 60,
                'burst_limit': 10,
                'strategy': 'fixed_window'
            },
            'input_validation': {
                'enabled': True,
                'max_message_length': 10000,
                'sanitize_html': True,
                'allowed_characters': 'strict_alphanumeric_plus_punctuation'
            },
            'audit_logging': {
                'enabled': True,
                'log_file': 'logs/security.log',
                'max_log_size_mb': 100,
                'backup_count': 10,
                'mask_pii': True
            },
            'access_control': {
                'enabled': True,
                'allowed_ips': [],
                'blocked_ips': [],
                'require_auth': True
            }
        }
        self._save_config()

    def _save_config(self):
        """Save configuration with strict file permissions."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            
            # Lock permissions to owner read/write only (0o600)
            if os.name == 'posix':
                os.chmod(self.config_path, 0o600)
                
        except Exception as e:
            logger.error(f"Error saving security config: {e}")

    # -------------------------------------------------------------------------
    # Encryption (AES-256-GCM)
    # -------------------------------------------------------------------------

    def encrypt_data(self, data: str) -> str:
        """
        Encrypt data using AES-256-GCM.
        Returns: base64(nonce + ciphertext + tag)
        """
        if not self.aesgcm:
            raise ValueError("Encryption system not initialized")
        
        # Generate unique 12-byte nonce for GCM
        nonce = secrets.token_bytes(12)
        
        # Encrypt (GCM handles the MAC tag automatically)
        ciphertext = self.aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        
        # Combine nonce + ciphertext for storage
        return base64.urlsafe_b64encode(nonce + ciphertext).decode('utf-8')

    def decrypt_data(self, encrypted_data: str) -> str:
        """
        Decrypt data using AES-256-GCM.
        Supports key rotation (tries current key, then rotation keys).
        """
        if not self.aesgcm:
            raise ValueError("Encryption system not initialized")

        try:
            raw_data = base64.urlsafe_b64decode(encrypted_data)
            
            # Extract nonce (first 12 bytes)
            nonce = raw_data[:12]
            ciphertext = raw_data[12:]
            
            # Try primary key
            try:
                return self.aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
            except InvalidTag:
                # Try rotation keys if primary fails
                for r_key in self.rotation_keys:
                    try:
                        return r_key.decrypt(nonce, ciphertext, None).decode('utf-8')
                    except InvalidTag:
                        continue
                raise InvalidTag("Decryption failed: Invalid key or corrupted data")
                
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise

    # -------------------------------------------------------------------------
    # Hashing (Argon2) - Use this for Passwords/API Keys
    # -------------------------------------------------------------------------

    def hash_secret(self, secret: str) -> str:
        """
        Hash a secret using Argon2 (Memory-hard hashing).
        NEVER encrypt passwords; always hash them.
        """
        return argon2.hash(secret)

    def verify_secret(self, secret: str, hash_str: str) -> bool:
        """Verify a secret against an Argon2 hash."""
        return argon2.verify(secret, hash_str)

    # -------------------------------------------------------------------------
    # Config Getters
    # -------------------------------------------------------------------------

    def get_section(self, section: str) -> Dict[str, Any]:
        """Safe getter for config sections."""
        return self.config.get(section, {})

    def is_feature_enabled(self, feature: str) -> bool:
        """Check if feature is enabled (format: 'section.key')."""
        try:
            section, key = feature.split('.', 1)
            return self.config.get(section, {}).get(key, False)
        except (ValueError, AttributeError):
            return False

    def get_rate_limit_config(self) -> Dict[str, Any]:
        """Get rate limiting configuration."""
        return self.config.get('rate_limiting', {
            'enabled': True,
            'requests_per_minute': 60,
            'burst_limit': 100,
            'per_guard': {
                'phishguard': 30,
                'smishguard': 30,
                'vishguard': 30
            }
        })

    def get_audit_logging_config(self) -> Dict[str, Any]:
        """Get audit logging configuration."""
        return self.config.get('audit_logging', {
            'enabled': True,
            'log_level': 'INFO',
            'log_file': 'logs/audit.log',
            'rotation': 'daily',
            'retention_days': 90
        })

    def update_config(self, section: str, key: str, value: Any):
        """Update config and save securely."""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        self._save_config()

# Create global security config instance
security_config = SecurityConfig()