from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple, Union
import logging
from datetime import datetime
import email.message
from email.header import decode_header
import os
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class EmailFetcher(ABC):
    """Base class for email fetcher implementations."""
    
    def __init__(self):
        """Initialize the email fetcher."""
        self.connection = None
        load_dotenv()
        self._validate_credentials()
    
    @abstractmethod
    def _validate_credentials(self):
        """Validate required credentials."""
        pass
    
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
        
    def move_to_junk(self, email_id: str) -> bool:
        """Move an email to the junk/spam folder."""
        if not self.connection:
            if not self.connect():
                return False
        
        try:
            self.connection.select('INBOX')
            self.connection.copy(email_id, 'Spam')
            self.connection.store(email_id, '+FLAGS', '\\Deleted')
            self.connection.expunge()
            return True
        except Exception as e:
            logger.error(f"Error moving email to Spam: {e}")
            return False
        
    def process_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw email data into a standardized format."""
        try:
            return {
                'id': email_data.get('id'),
                'from': email_data.get('from'),
                'to': email_data.get('to'),
                'subject': email_data.get('subject'),
                'body': email_data.get('body'),
                'date': email_data.get('date', datetime.now().isoformat()),
                'attachments': email_data.get('attachments', []),
                'metadata': {
                    'provider': self.__class__.__name__,
                    'folder': email_data.get('folder', 'INBOX'),
                    'flags': email_data.get('flags', []),
                    'size': email_data.get('size', 0)
                }
            }
        except Exception as e:
            logger.error(f"Error processing email: {e}")
            return {}
    
    def _decode_header(self, header: str) -> str:
        """Decode email header.
        
        Args:
            header: The email header to decode
            
        Returns:
            str: Decoded header text
        """
        if header is None:
            return ""
        try:
            decoded_header: List[Tuple[Union[str, bytes], Optional[str]]] = decode_header(header)
            return " ".join(
                text.decode(charset or 'utf-8') if isinstance(text, bytes) else text
                for text, charset in decoded_header
            )
        except Exception as e:
            logger.error(f"Error decoding header: {e}")
            return str(header)
    
    def _extract_body(self, msg: email.message.Message) -> str:
        """Extract email body handling multipart messages."""
        if msg.is_multipart():
            body = ''
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            return body
        return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect() 