import imaplib
import email
from email.header import decode_header
import os
from datetime import datetime
import logging
from typing import List, Dict, Any
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class OutlookDoggy:
    def __init__(self):
        load_dotenv()
        self.email = os.getenv('OUTLOOK_EMAIL')
        self.password = os.getenv('OUTLOOK_PASSWORD')
        self.imap_server = "outlook.office365.com"
        self.imap_port = 993

    def connect(self) -> imaplib.IMAP4_SSL:
        """Connect to Outlook IMAP server."""
        try:
            imap = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            imap.login(self.email, self.password)
            return imap
        except Exception as e:
            logger.error(f"Failed to connect to Outlook: {e}")
            raise

    def fetch_emails(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch emails from Outlook using IMAP."""
        try:
            imap = self.connect()
            imap.select('INBOX')
            
            # Search for all emails
            _, message_numbers = imap.search(None, 'ALL')
            email_list = []
            
            # Get the most recent emails
            for num in message_numbers[0].split()[-limit:]:
                _, msg_data = imap.fetch(num, '(RFC822)')
                email_body = msg_data[0][1]
                email_message = email.message_from_bytes(email_body)
                
                # Extract email details
                subject = self._decode_header(email_message['subject'])
                from_addr = self._decode_header(email_message['from'])
                date = email_message['date']
                
                # Get email body
                body = ""
                if email_message.is_multipart():
                    for part in email_message.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode()
                            break
                else:
                    body = email_message.get_payload(decode=True).decode()
                
                email_list.append({
                    'subject': subject,
                    'from': from_addr,
                    'date': date,
                    'body': body,
                    'raw_email': email_body
                })
            
            imap.close()
            imap.logout()
            return email_list
            
        except Exception as e:
            logger.error(f"Error fetching Outlook emails: {e}")
            raise

    def _decode_header(self, header: str) -> str:
        """Decode email header."""
        if header is None:
            return ""
        decoded_header = decode_header(header)
        return " ".join(
            text.decode(charset or 'utf-8') if isinstance(text, bytes) else text
            for text, charset in decoded_header
        )

    def move_to_junk(self, message_id: str) -> bool:
        """Move an email to Junk folder."""
        try:
            imap = self.connect()
            imap.select('INBOX')
            imap.copy(message_id, 'Junk')
            imap.store(message_id, '+FLAGS', '\\Deleted')
            imap.expunge()
            imap.close()
            imap.logout()
            return True
        except Exception as e:
            logger.error(f"Error moving email to Junk: {e}")
            return False

if __name__ == "__main__":
    # Test the fetcher
    fetcher = OutlookDoggy()
    emails = fetcher.fetch_emails(limit=5)
    for email in emails:
        print(f"From: {email['from']}")
        print(f"Subject: {email['subject']}")
        print("-" * 50) 