from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime

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
            
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect() 