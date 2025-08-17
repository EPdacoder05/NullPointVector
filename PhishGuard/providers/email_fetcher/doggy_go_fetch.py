from typing import List, Dict, Any
from .secure_base import SecureEmailFetcher

class SimpleEmailFetcher(SecureEmailFetcher):
    """Simple email fetcher that inherits security features but provides a simpler interface."""
    
    def fetch_emails(self, folder: str = 'INBOX', limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch emails with a simpler interface.
        
        Returns:
            List of dictionaries with keys: 'subject', 'sender', 'date', 'body'
        """
        # Use the secure implementation but return simplified data
        secure_emails = super().fetch_emails(folder, limit)
        
        # Convert to simple format
        simple_emails = []
        for email in secure_emails:
            simple_emails.append({
                'subject': email.get('subject', ''),
                'sender': email.get('from', ''),
                'date': email.get('date', ''),
                'body': email.get('body', '')
            })
            
        return simple_emails 