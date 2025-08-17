import imaplib
import email
from email.header import decode_header
import os
from dotenv import load_dotenv
from email_fetcher import EmailFetcher
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

class YahooDoggy(EmailFetcher):
    """Yahoo email fetcher implementation."""
    
    def __init__(self):
        """Initialize Yahoo fetcher with configuration."""
        load_dotenv()
        self.imap_host = 'imap.mail.yahoo.com'
        self.imap_user = os.getenv('YAHOO_USER')
        self.imap_pass = os.getenv('YAHOO_PASS')
        
        if not all([self.imap_user, self.imap_pass]):
            raise ValueError("Missing Yahoo credentials in environment variables")

    def _extract_body(self, msg):
        """Extract email body handling multipart messages."""
        if msg.is_multipart():
            body = ''
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            return body
        return msg.get_payload(decode=True).decode('utf-8', errors='ignore')

    def fetch_emails(self):
        """Fetch emails from Yahoo mailbox."""
        emails = []
        try:
            with imaplib.IMAP4_SSL(self.imap_host) as mail:
                mail.login(self.imap_user, self.imap_pass)
                logger.info("Successfully logged in to Yahoo IMAP server")
                
                mail.select('inbox')
                status, data = mail.search(None, 'ALL')
                email_ids = data[0].split()
                
                logger.info(f"Found {len(email_ids)} emails to process")
                
                for email_id in email_ids:
                    try:
                        status, data = mail.fetch(email_id, '(RFC822)')
                        for response_part in data:
                            if isinstance(response_part, tuple):
                                msg = email.message_from_bytes(response_part[1])
                                emails.append({
                                    'subject': decode_header(msg['Subject'])[0][0],
                                    'sender': msg.get('From'),
                                    'date': msg.get('Date'),
                                    'body': self._extract_body(msg)
                                })
                    except Exception as e:
                        logger.error(f"Error processing email ID {email_id}: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to fetch emails: {e}")
            raise
            
        logger.info(f"Successfully processed {len(emails)} emails")
        return emails

if __name__ == "__main__":
    # Test the fetcher
    fetcher = YahooDoggy()
    emails = fetcher.fetch_emails()
    for email in emails:
        print(f"From: {email['sender']}")
        print(f"Subject: {email['subject']}")
        print("-" * 50)