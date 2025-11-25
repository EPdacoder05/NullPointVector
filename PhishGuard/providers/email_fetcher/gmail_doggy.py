import imaplib
import email
from email.header import decode_header
import os
from datetime import datetime
import logging
from typing import List, Dict, Any
from dotenv import load_dotenv

# Update the import to use base_fetcher (has IP extraction)
from .base_fetcher import EmailFetcher

logger = logging.getLogger(__name__)

class GmailDoggy(EmailFetcher):
    """Gmail email fetcher implementation."""
    
    def __init__(self):
        """Initialize Gmail fetcher."""
        super().__init__()
        load_dotenv()
        self._validate_credentials()
    
    def _validate_credentials(self):
        """Validate required credentials."""
        self.username = os.getenv('GMAIL_USER')
        self.password = os.getenv('GMAIL_PASS')
        if not self.username or not self.password:
            raise ValueError("Gmail credentials not found in environment variables")
    
    def connect(self) -> bool:
        """Connect to Gmail IMAP server."""
        try:
            self.connection = imaplib.IMAP4_SSL('imap.gmail.com')
            self.connection.login(self.username, self.password)
            return True
        except Exception as e:
            logger.error(f"Error connecting to Gmail: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from Gmail IMAP server."""
        if self.connection:
            try:
                self.connection.logout()
            except Exception as e:
                logger.error(f"Error disconnecting from Gmail: {e}")
    
    def fetch_emails(self, folder: str = 'INBOX', limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch emails from Gmail."""
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
            logger.error(f"Error fetching emails from Gmail: {e}")
            return []
    
    def move_to_junk(self, email_id: str) -> bool:
        """Move an email to Gmail's Spam folder."""
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
    
    def _decode_header(self, header: str) -> str:
        """Decode email header."""
        if header is None:
            return ""
        decoded_header = decode_header(header)
        return " ".join(
            text.decode(charset or 'utf-8') if isinstance(text, bytes) else text
            for text, charset in decoded_header
        )
    
    def _extract_body(self, msg: email.message.Message) -> str:
        """Extract email body handling multipart messages."""
        if msg.is_multipart():
            body = ''
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            return body
        return msg.get_payload(decode=True).decode('utf-8', errors='ignore')

#if __name__ == "__main__":
    # Test the fetcher
 #   fetcher = GmailDoggy()
  #  emails = fetcher.fetch_emails()
   # for email in emails:
    #    print(f"From: {email['sender']}")
     #   print(f"Subject: {email['subject']}")
      #  print("-" * 50)