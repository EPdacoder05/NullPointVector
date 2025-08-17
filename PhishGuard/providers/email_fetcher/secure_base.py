from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple, Union
import logging
from datetime import datetime
import email
from email.header import decode_header
import os
import re
import ipaddress
from urllib.parse import urlparse
import hashlib
import hmac
import time
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class SecureEmailFetcher(ABC):
    """Security-focused base class for email fetcher implementations."""
    
    def __init__(self):
        """Initialize the secure email fetcher."""
        self.connection = None
        self.rate_limit = 100  # requests per minute
        self.request_times = []
        self.suspicious_ips = set()
        self.blocked_domains = set()
        self.phishy_bizz_folder = "Phishy_Bizz"
        load_dotenv()
        self._validate_credentials()
        self._init_security_patterns()
        self._validate_phishy_bizz_folder()
    
    def _validate_phishy_bizz_folder(self) -> bool:
        """Validate that Phishy_Bizz folder exists.
        
        Returns:
            bool: True if folder exists, False otherwise
        """
        if not os.path.exists(self.phishy_bizz_folder):
            logger.error(f"Required folder '{self.phishy_bizz_folder}' does not exist")
            return False
        return True
    
    def move_to_phishy_bizz(self, email_id: str) -> bool:
        """Move an email to the Phishy_Bizz folder.
        
        Args:
            email_id: The ID of the email to move
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self._validate_phishy_bizz_folder():
            logger.error("Cannot move email - Phishy_Bizz folder validation failed")
            return False
            
        try:
            # Provider-specific implementation will handle the actual move
            return self._move_email_to_folder(email_id, self.phishy_bizz_folder)
        except Exception as e:
            logger.error(f"Failed to move email to Phishy_Bizz: {e}")
            return False
    
    @abstractmethod
    def _move_email_to_folder(self, email_id: str, folder: str) -> bool:
        """Provider-specific implementation for moving emails.
        
        Args:
            email_id: The ID of the email to move
            folder: The destination folder
            
        Returns:
            bool: True if successful, False otherwise
        """
        pass
    
    def _init_security_patterns(self):
        """Initialize security patterns for various attacks."""
        # XSS patterns
        self.xss_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'data:text/html',
            r'vbscript:',
            r'expression\s*\(',
            r'url\s*\(',
            r'eval\s*\(',
            r'document\.',
            r'window\.',
            r'location\.',
            r'alert\s*\(',
            r'confirm\s*\(',
            r'prompt\s*\('
        ]
        
        # SQL Injection patterns
        self.sql_patterns = [
            r'(\%27)|(\')|(\-\-)',
            r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)',
            r'exec\s*xp_',
            r'exec\s*sp_',
            r'select\s*.*from',
            r'insert\s*.*into',
            r'update\s*.*set',
            r'delete\s*.*from',
            r'drop\s*.*table',
            r'truncate\s*.*table'
        ]
        
        # Command Injection patterns
        self.cmd_patterns = [
            r'[;&|`\$]',
            r'(\b(cat|chmod|curl|wget|nc|netcat|bash|sh|powershell|cmd)\b)',
            r'(\b(rm|del|mkdir|touch|echo)\b)',
            r'(\b(grep|find|ls|dir)\b)'
        ]
        
        # Email spoofing patterns
        self.spoof_patterns = [
            r'From:\s*[^<]*<[^>]*@[^>]*>',
            r'Reply-To:\s*[^<]*<[^>]*@[^>]*>',
            r'Return-Path:\s*[^<]*<[^>]*@[^>]*>'
        ]
        
        # Compile patterns
        self.xss_regex = re.compile('|'.join(self.xss_patterns), re.IGNORECASE)
        self.sql_regex = re.compile('|'.join(self.sql_patterns), re.IGNORECASE)
        self.cmd_regex = re.compile('|'.join(self.cmd_patterns), re.IGNORECASE)
        self.spoof_regex = re.compile('|'.join(self.spoof_patterns), re.IGNORECASE)
    
    def _check_rate_limit(self) -> bool:
        """Check if current request exceeds rate limit."""
        current_time = time.time()
        self.request_times = [t for t in self.request_times if current_time - t < 60]
        if len(self.request_times) >= self.rate_limit:
            return False
        self.request_times.append(current_time)
        return True
    
    def _validate_input(self, text: str) -> bool:
        """Validate input for various security threats."""
        if not text:
            return True
            
        # Check for XSS
        if self.xss_regex.search(text):
            logger.warning("Potential XSS attack detected")
            return False
            
        # Check for SQL Injection
        if self.sql_regex.search(text):
            logger.warning("Potential SQL injection detected")
            return False
            
        # Check for Command Injection
        if self.cmd_regex.search(text):
            logger.warning("Potential command injection detected")
            return False
            
        return True
    
    def _check_email_spoofing(self, email_msg: email.message.Message) -> bool:
        """Check for email spoofing attempts."""
        headers = str(email_msg)
        if self.spoof_regex.search(headers):
            logger.warning("Potential email spoofing detected")
            return False
        return True
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address and check against blocklist."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj in self.suspicious_ips:
                return False
            return True
        except ValueError:
            return False
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain and check against blocklist."""
        if domain in self.blocked_domains:
            return False
        return True
    
    def _sanitize_output(self, text: str) -> str:
        """Sanitize output to prevent XSS and injection attacks."""
        if not text:
            return ""
        # Remove potentially dangerous characters
        text = re.sub(r'[<>]', '', text)
        # Escape special characters
        text = text.replace('&', '&amp;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        return text
    
    @abstractmethod
    def _validate_credentials(self):
        """Validate required credentials."""
        pass
    
    @abstractmethod
    def connect(self) -> bool:
        """Connect to the email server with security checks."""
        if not self._check_rate_limit():
            raise Exception("Rate limit exceeded")
        pass
        
    @abstractmethod
    def disconnect(self):
        """Disconnect from the email server."""
        pass
        
    @abstractmethod
    def fetch_emails(self, folder: str = 'INBOX', limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch emails with security checks."""
        if not self._check_rate_limit():
            raise Exception("Rate limit exceeded")
        if not self._validate_input(folder):
            raise Exception("Invalid folder name")
        pass
        
    def process_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw email data with security checks."""
        try:
            # Validate all inputs
            for key, value in email_data.items():
                if isinstance(value, str) and not self._validate_input(value):
                    raise Exception(f"Invalid input detected in {key}")
            
            # Sanitize all outputs
            processed = {
                'id': self._sanitize_output(str(email_data.get('id', ''))),
                'from': self._sanitize_output(email_data.get('from', '')),
                'to': self._sanitize_output(email_data.get('to', '')),
                'subject': self._sanitize_output(email_data.get('subject', '')),
                'body': self._sanitize_output(email_data.get('body', '')),
                'date': email_data.get('date', datetime.now().isoformat()),
                'attachments': [
                    {
                        'name': self._sanitize_output(att.get('name', '')),
                        'type': self._sanitize_output(att.get('type', '')),
                        'size': att.get('size', 0)
                    }
                    for att in email_data.get('attachments', [])
                ],
                'metadata': {
                    'provider': self.__class__.__name__,
                    'folder': self._sanitize_output(email_data.get('folder', 'INBOX')),
                    'flags': [self._sanitize_output(f) for f in email_data.get('flags', [])],
                    'size': email_data.get('size', 0)
                }
            }
            
            return processed
            
        except Exception as e:
            logger.error(f"Error processing email: {e}")
            return {}
    
    def __enter__(self):
        """Context manager entry with security checks."""
        if not self.connect():
            raise Exception("Failed to establish secure connection")
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect() 