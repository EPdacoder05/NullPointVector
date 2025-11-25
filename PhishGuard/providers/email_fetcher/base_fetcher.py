from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime
import sys
from pathlib import Path

# Add project root to path for security imports
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from utils.security.input_validator import input_validator

logger = logging.getLogger(__name__)

class EmailFetcher(ABC):
    """Base class for email fetcher implementations."""
    
    def __init__(self):
        """Initialize the email fetcher."""
        self.connection = None
        
    @abstractmethod
    def connect(self) -> bool:
        """Connect to the email server."""
        pass
        
    @abstractmethod
    def disconnect(self):
        """Disconnect from the email server."""
        pass
        
    @abstractmethod
    def fetch_emails(self, folder: str = 'INBOX', limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch emails from the specified folder."""
        pass
        
    @abstractmethod
    def move_to_junk(self, email_id: str) -> bool:
        """Move an email to the junk/spam folder."""
        pass
        
    def process_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process raw email data into a standardized format.
        SECURITY: Validates and sanitizes all headers to prevent exploits.
        """
        try:
            # Extract and SECURELY sanitize headers
            raw_headers = email_data.get('headers', {})
            sanitized_headers = {}
            
            if isinstance(raw_headers, dict):
                for key, value in raw_headers.items():
                    # Sanitize header key (prevent injection via header names)
                    safe_key = input_validator.sanitize_string(str(key), max_length=100)
                    
                    # Sanitize header value (prevent XSS, command injection, etc.)
                    if isinstance(value, list):
                        # Handle multi-value headers (like Received)
                        sanitized_values = []
                        for v in value[:10]:  # Limit to 10 values (DoS prevention)
                            safe_value = input_validator.sanitize_string(str(v), max_length=500)
                            sanitized_values.append(safe_value)
                        sanitized_headers[safe_key] = sanitized_values
                    else:
                        # Single value headers
                        safe_value = input_validator.sanitize_string(str(value), max_length=500)
                        sanitized_headers[safe_key] = safe_value
            
            # Extract IP addresses from headers (SECURELY)
            ip_addresses = []
            received_headers = sanitized_headers.get('received', [])
            if isinstance(received_headers, list):
                import re
                for received in received_headers:
                    if isinstance(received, str):
                        # Extract all IPv4 patterns, then validate
                        potential_ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', received)
                        for ip in potential_ips:
                            # Validate with input_validator (returns valid IP string or empty)
                            valid_ip = input_validator.validate_ip_address(ip)
                            if valid_ip:
                                # Skip private/localhost IPs
                                if not valid_ip.startswith(('127.', '10.', '192.168.', '172.16.', '172.31.')):
                                    ip_addresses.append(valid_ip)
                                    logger.debug(f"📍 Extracted valid public IP: {valid_ip}")
            
            # Also check X-Originating-IP header (prioritize this)
            x_orig_ip = sanitized_headers.get('x_originating_ip') or sanitized_headers.get('x-originating-ip')
            if x_orig_ip:
                # Remove brackets if present: [123.45.67.89] → 123.45.67.89
                clean_ip = x_orig_ip.strip('[]').strip()
                valid_ip = input_validator.validate_ip_address(clean_ip)
                if valid_ip and not valid_ip.startswith(('127.', '10.', '192.168.')):
                    ip_addresses.insert(0, valid_ip)  # Prioritize this header
                    logger.debug(f"📍 X-Originating-IP: {valid_ip}")
            
            return {
                'id': email_data.get('id'),
                'from': email_data.get('from'),
                'to': email_data.get('to'),
                'subject': email_data.get('subject'),
                'body': email_data.get('body'),
                'date': email_data.get('date', datetime.now().isoformat()),
                'attachments': email_data.get('attachments', []),
                'headers': sanitized_headers,  # SECURELY sanitized headers
                'ip_addresses': ip_addresses,  # Extracted and validated IPs
                'metadata': {
                    'provider': self.__class__.__name__,
                    'folder': email_data.get('folder', 'INBOX'),
                    'flags': email_data.get('flags', []),
                    'size': email_data.get('size', 0)
                }
            }
        except Exception as e:
            logger.error(f"Error processing email: {e}")
            import traceback
            traceback.print_exc()
            return {}
            
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect() 