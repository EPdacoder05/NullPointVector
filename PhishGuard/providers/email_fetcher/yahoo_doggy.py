import imaplib
import email
from email.header import decode_header
import os
from datetime import datetime
import logging
from typing import List, Dict, Any, Optional, Tuple, Union
from dotenv import load_dotenv

# Import from base.py
from .base import EmailFetcher

logger = logging.getLogger(__name__)

class YahooDoggy(EmailFetcher):
    """Yahoo email fetcher implementation."""
    
    def __init__(self):
        """Initialize Yahoo fetcher."""
        super().__init__()
        load_dotenv()
        self._validate_credentials()
    
    def _validate_credentials(self):
        """Validate required credentials."""
        self.username = os.getenv('YAHOO_USER')
        self.password = os.getenv('YAHOO_PASS')
        if not self.username or not self.password:
            raise ValueError("Yahoo credentials not found in environment variables")
    
    def connect(self) -> bool:
        """Connect to Yahoo IMAP server."""
        try:
            self.connection = imaplib.IMAP4_SSL('imap.mail.yahoo.com')
            self.connection.login(self.username, self.password)
            return True
        except Exception as e:
            logger.error(f"Error connecting to Yahoo: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from Yahoo IMAP server."""
        if self.connection:
            try:
                self.connection.logout()
            except Exception as e:
                logger.error(f"Error disconnecting from Yahoo: {e}")
    
    def fetch_emails(self, folder: str = 'INBOX', limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch emails from Yahoo."""
        if not self.connection:
            if not self.connect():
                return []
        
        try:
            self.connection.select(folder)
            _, messages = self.connection.search(None, 'ALL')
            email_ids = messages[0].split()
            
            # Limit the number of emails
            email_ids = email_ids[-limit:] if limit else email_ids
            
            emails = []
            for email_id in email_ids:
                _, msg_data = self.connection.fetch(email_id, '(RFC822)')
                email_body = msg_data[0][1]
                email_message = email.message_from_bytes(email_body)
                
                # Process the email
                processed_email = self.process_email({
                    'id': email_id.decode(),
                    'from': self._decode_header(email_message['From']),
                    'to': self._decode_header(email_message['To']),
                    'subject': self._decode_header(email_message['Subject']),
                    'body': self._extract_body(email_message),
                    'date': email_message['Date'],
                    'folder': folder
                })
                emails.append(processed_email)
            
            return emails
        except Exception as e:
            logger.error(f"Error fetching emails from Yahoo: {e}")
            return []
    
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
        """Extract email body handling multipart messages.
        
        Args:
            msg: The email message to extract body from
            
        Returns:
            str: Extracted email body text
        """
        try:
            if msg.is_multipart():
                body = ''
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        try:
                            body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except Exception as e:
                            logger.error(f"Error decoding part: {e}")
                            continue
                return body
            return msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Error extracting body: {e}")
            return ""

# if __name__ == "__main__":
#     # Test the fetcher
#     fetcher = YahooDoggy()
#     emails = fetcher.fetch_emails()
#     for email in emails:
#         print(f"From: {email['from']}")
#         print(f"Subject: {email['subject']}")
#         print("-" * 50)