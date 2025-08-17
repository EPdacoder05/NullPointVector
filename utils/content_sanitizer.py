import re
import html
import bleach
from urllib.parse import urlparse, unquote
import logging
from typing import Dict, Any, List
import json

logger = logging.getLogger(__name__)

class ContentSanitizer:
    def __init__(self):
        self.allowed_tags = ['p', 'br', 'b', 'i', 'u', 'em', 'strong']
        self.allowed_attributes = {'a': ['href', 'title']}
        self.suspicious_patterns = {
            'urls': [
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                r'bit\.ly/\w+',
                r't\.co/\w+',
                r'goo\.gl/\w+'
            ],
            'phone_numbers': [
                r'\+?\d{10,}',
                r'\d{3}[-.]?\d{3}[-.]?\d{4}'
            ],
            'emails': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ]
        }
    
    def sanitize_email(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize email content."""
        try:
            # Sanitize subject
            content['subject'] = self._sanitize_text(content.get('subject', ''))
            
            # Sanitize body
            content['body'] = self._sanitize_html(content.get('body', ''))
            
            # Sanitize sender
            content['sender'] = self._sanitize_email_address(content.get('sender', ''))
            
            # Extract and validate URLs
            content['urls'] = self._extract_urls(content['body'])
            
            # Extract and validate attachments
            content['attachments'] = self._validate_attachments(content.get('attachments', []))
            
            return content
        except Exception as e:
            logger.error(f"Error sanitizing email: {e}")
            raise
    
    def sanitize_sms(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize SMS content."""
        try:
            # Sanitize message body
            content['body'] = self._sanitize_text(content.get('body', ''))
            
            # Sanitize sender number
            content['sender'] = self._sanitize_phone_number(content.get('sender', ''))
            
            # Extract and validate URLs
            content['urls'] = self._extract_urls(content['body'])
            
            # Check for suspicious patterns
            content['suspicious_patterns'] = self._check_suspicious_patterns(content['body'])
            
            return content
        except Exception as e:
            logger.error(f"Error sanitizing SMS: {e}")
            raise
    
    def sanitize_voice(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize voice call content."""
        try:
            # Sanitize transcript
            content['transcript'] = self._sanitize_text(content.get('transcript', ''))
            
            # Sanitize caller ID
            content['caller_id'] = self._sanitize_phone_number(content.get('caller_id', ''))
            
            # Extract and validate metadata
            content['metadata'] = self._validate_metadata(content.get('metadata', {}))
            
            # Check for suspicious patterns in transcript
            content['suspicious_patterns'] = self._check_suspicious_patterns(content['transcript'])
            
            return content
        except Exception as e:
            logger.error(f"Error sanitizing voice: {e}")
            raise
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize plain text."""
        # Remove null bytes
        text = text.replace('\0', '')
        
        # Decode HTML entities
        text = html.unescape(text)
        
        # Remove control characters
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
        
        return text.strip()
    
    def _sanitize_html(self, html_content: str) -> str:
        """Sanitize HTML content."""
        # Use bleach to sanitize HTML
        return bleach.clean(
            html_content,
            tags=self.allowed_tags,
            attributes=self.allowed_attributes,
            strip=True
        )
    
    def _sanitize_email_address(self, email: str) -> str:
        """Sanitize email address."""
        # Basic email validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return ''
        return email.lower()
    
    def _sanitize_phone_number(self, phone: str) -> str:
        """Sanitize phone number."""
        # Remove non-numeric characters
        digits = re.sub(r'\D', '', phone)
        
        # Validate length
        if len(digits) < 10 or len(digits) > 15:
            return ''
        
        return digits
    
    def _extract_urls(self, text: str) -> List[Dict[str, Any]]:
        """Extract and validate URLs from text."""
        urls = []
        for pattern in self.suspicious_patterns['urls']:
            for match in re.finditer(pattern, text):
                url = match.group()
                try:
                    parsed = urlparse(url)
                    urls.append({
                        'original': url,
                        'parsed': {
                            'scheme': parsed.scheme,
                            'netloc': parsed.netloc,
                            'path': parsed.path,
                            'query': parsed.query
                        },
                        'is_shortened': any(domain in url.lower() for domain in ['bit.ly', 't.co', 'goo.gl'])
                    })
                except Exception as e:
                    logger.warning(f"Error parsing URL {url}: {e}")
        return urls
    
    def _validate_attachments(self, attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate email attachments."""
        valid_attachments = []
        for attachment in attachments:
            try:
                # Check file extension
                ext = attachment.get('filename', '').split('.')[-1].lower()
                if ext in ['exe', 'bat', 'cmd', 'sh', 'js', 'vbs']:
                    continue
                
                # Check file size (max 10MB)
                if attachment.get('size', 0) > 10 * 1024 * 1024:
                    continue
                
                valid_attachments.append(attachment)
            except Exception as e:
                logger.warning(f"Error validating attachment: {e}")
        return valid_attachments
    
    def _validate_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Validate call metadata."""
        try:
            # Ensure required fields
            required_fields = ['duration', 'timestamp', 'call_type']
            for field in required_fields:
                if field not in metadata:
                    metadata[field] = None
            
            # Validate duration
            if metadata['duration'] is not None:
                metadata['duration'] = max(0, min(metadata['duration'], 3600))  # Max 1 hour
            
            # Validate timestamp
            if metadata['timestamp'] is not None:
                if not isinstance(metadata['timestamp'], (int, float)):
                    metadata['timestamp'] = None
            
            return metadata
        except Exception as e:
            logger.warning(f"Error validating metadata: {e}")
            return {}
    
    def _check_suspicious_patterns(self, text: str) -> Dict[str, List[str]]:
        """Check for suspicious patterns in text."""
        patterns = {}
        for pattern_type, pattern_list in self.suspicious_patterns.items():
            matches = []
            for pattern in pattern_list:
                for match in re.finditer(pattern, text):
                    matches.append(match.group())
            if matches:
                patterns[pattern_type] = matches
        return patterns 