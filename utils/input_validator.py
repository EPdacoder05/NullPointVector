"""
Input validation utility for "Guards"
"""

import re
from typing import Dict, Any, Optional, List
from config.security_config import security_config

class InputValidator:
    """Input validator for user data and messages."""
    
    def __init__(self):
        self.config = security_config.get_input_validation_config()
        
    def validate_message(self, message: str) -> Tuple[bool, Optional[str]]:
        """Validate a message.
        
        Args:
            message: Message to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.config.get('enabled', True):
            return True, None
            
        # Check message length
        max_length = self.config.get('max_message_length', 10000)
        if len(message) > max_length:
            return False, f"Message exceeds maximum length of {max_length} characters"
            
        # Check allowed characters
        allowed_chars = self.config.get('allowed_characters', 'a-zA-Z0-9\\s\\.,!?@#$%^&*()_+-=[]{}|;:"\'<>/')
        pattern = f'^[{allowed_chars}]+$'
        if not re.match(pattern, message):
            return False, "Message contains disallowed characters"
            
        return True, None
        
    def validate_email(self, email: str) -> Tuple[bool, Optional[str]]:
        """Validate an email address.
        
        Args:
            email: Email address to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not email:
            return False, "Email address is required"
            
        # Basic email format validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return False, "Invalid email format"
            
        # Check for common disposable email domains
        disposable_domains = [
            'tempmail.com',
            'throwawaymail.com',
            'mailinator.com',
            'guerrillamail.com'
        ]
        domain = email.split('@')[1].lower()
        if domain in disposable_domains:
            return False, "Disposable email addresses are not allowed"
            
        return True, None
        
    def validate_phone(self, phone: str) -> Tuple[bool, Optional[str]]:
        """Validate a phone number.
        
        Args:
            phone: Phone number to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not phone:
            return False, "Phone number is required"
            
        # Remove non-digit characters
        digits = re.sub(r'\D', '', phone)
        
        # Check length (assuming US numbers)
        if len(digits) != 10:
            return False, "Phone number must be 10 digits"
            
        return True, None
        
    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate a URL.
        
        Args:
            url: URL to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url:
            return False, "URL is required"
            
        # Basic URL format validation
        pattern = r'^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$'
        if not re.match(pattern, url):
            return False, "Invalid URL format"
            
        # Check for common phishing domains
        phishing_domains = [
            'paypal-secure.com',
            'amazon-secure.com',
            'apple-secure.com',
            'microsoft-secure.com'
        ]
        domain = url.split('/')[2].lower()
        if domain in phishing_domains:
            return False, "Suspicious domain detected"
            
        return True, None
        
    def validate_json(self, data: Dict[str, Any], required_fields: List[str]) -> Tuple[bool, Optional[str]]:
        """Validate JSON data.
        
        Args:
            data: JSON data to validate
            required_fields: List of required field names
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not isinstance(data, dict):
            return False, "Data must be a dictionary"
            
        # Check required fields
        for field in required_fields:
            if field not in data:
                return False, f"Missing required field: {field}"
                
        return True, None
        
    def sanitize_input(self, input_str: str) -> str:
        """Sanitize user input.
        
        Args:
            input_str: Input string to sanitize
            
        Returns:
            Sanitized string
        """
        if not input_str:
            return ""
            
        # Remove HTML tags
        input_str = re.sub(r'<[^>]+>', '', input_str)
        
        # Remove control characters
        input_str = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', input_str)
        
        # Remove multiple spaces
        input_str = re.sub(r'\s+', ' ', input_str)
        
        return input_str.strip()

# Create global input validator instance
input_validator = InputValidator() 