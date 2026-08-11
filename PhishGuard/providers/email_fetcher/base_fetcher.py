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
        
    def extract_auth_headers(self, email_message) -> dict:
        """Auth stamps needed for known-good short-circuit (SPF/DKIM/DMARC)."""
        return {
            "received": email_message.get_all("Received", []) or [],
            "return_path": email_message.get("Return-Path"),
            "message_id": email_message.get("Message-ID"),
            "x_originating_ip": email_message.get("X-Originating-IP"),
            "x_mailer": email_message.get("X-Mailer"),
            "authentication_results": email_message.get("Authentication-Results"),
            "received_spf": email_message.get("Received-SPF"),
            "dkim_signature": email_message.get("DKIM-Signature"),
        }

    def extract_body_text(self, msg) -> str:
        """Prefer text/plain; fall back to stripped HTML (image-heavy retail mail)."""
        import re
        plain, html = [], []
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = (part.get_content_type() or "").lower()
                    disp = str(part.get("Content-Disposition") or "").lower()
                    if "attachment" in disp:
                        continue
                    try:
                        payload = part.get_payload(decode=True) or b""
                        text = payload.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    if ctype == "text/plain":
                        plain.append(text)
                    elif ctype == "text/html":
                        html.append(text)
            else:
                ctype = (msg.get_content_type() or "").lower()
                try:
                    payload = msg.get_payload(decode=True) or b""
                    text = payload.decode("utf-8", errors="ignore")
                except Exception:
                    text = ""
                if ctype == "text/html":
                    html.append(text)
                else:
                    plain.append(text)
        except Exception as e:
            logger.error("extract_body_text failed: %s", e)
            return ""
        body = "\n".join(plain).strip()
        if body:
            return body
        raw_html = "\n".join(html)
        if not raw_html:
            return ""
        # Cheap HTML → text so empty-body retail mail still has features.
        raw_html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw_html)
        raw_html = re.sub(r"(?is)<br\s*/?>", "\n", raw_html)
        raw_html = re.sub(r"(?is)</p>", "\n", raw_html)
        raw_html = re.sub(r"(?is)<[^>]+>", " ", raw_html)
        raw_html = re.sub(r"&nbsp;", " ", raw_html)
        raw_html = re.sub(r"\s+", " ", raw_html).strip()
        return raw_html[:50000]

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
                # Auth stamps are long; truncating at 500 chars drops dmarc=pass and
                # breaks known-good short-circuit → GitHub/Google FP quarantine.
                _AUTH_KEYS = {
                    "authentication_results", "authentication-results",
                    "received_spf", "received-spf",
                    "dkim_signature", "dkim-signature",
                    "return_path", "return-path",
                }
                for key, value in raw_headers.items():
                    safe_key = input_validator.sanitize_string(str(key), max_length=100)
                    max_len = 4000 if safe_key.lower() in _AUTH_KEYS else 500
                    if isinstance(value, list):
                        sanitized_values = []
                        for v in value[:10]:
                            # Auth/received: preserve raw (no HTML escape — breaks SPF tokens)
                            if safe_key.lower() in _AUTH_KEYS or safe_key.lower() == "received":
                                s = str(v or "")[:max_len].replace("\x00", "").strip()
                            else:
                                s = input_validator.sanitize_string(str(v), max_length=max_len)
                            sanitized_values.append(s)
                        sanitized_headers[safe_key] = sanitized_values
                    else:
                        if safe_key.lower() in _AUTH_KEYS:
                            sanitized_headers[safe_key] = (
                                str(value or "")[:max_len].replace("\x00", "").strip()
                            )
                        else:
                            sanitized_headers[safe_key] = input_validator.sanitize_string(
                                str(value), max_length=max_len
                            )
            
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