import imaplib
import email
from email.header import decode_header
import os
import logging
from typing import List, Dict, Any, Optional, Tuple, Union
from dotenv import load_dotenv

from .base_fetcher import EmailFetcher

logger = logging.getLogger(__name__)


class YahooDoggy(EmailFetcher):
    """Yahoo email fetcher — auth headers + HTML body fallback."""

    def __init__(self):
        super().__init__()
        load_dotenv()
        self._validate_credentials()

    def _validate_credentials(self):
        self.username = os.getenv("YAHOO_USER")
        self.password = os.getenv("YAHOO_PASS")
        if self.username and self.password:
            return
        try:
            from common.mailbox_store import list_for_user, get_secret
            sub = (os.getenv("NULLPOINT_INGEST_SUB") or "anonymous").strip()
            for row in list_for_user(sub):
                if (row.get("provider") or "").lower() not in ("yahoo",):
                    continue
                secret = get_secret(sub, "yahoo", row["account"])
                if secret:
                    self.username = row["account"]
                    self.password = secret
                    return
        except Exception as e:
            logger.error("mailbox_store yahoo fallback: %s", e)
        if not self.username or not self.password:
            raise ValueError("Yahoo credentials not found in environment variables or mailbox_store")

    def connect(self) -> bool:
        try:
            self.connection = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
            self.connection.login(self.username, self.password)
            return True
        except Exception as e:
            logger.error("Error connecting to Yahoo: %s", e)
            return False

    def disconnect(self):
        if self.connection:
            try:
                self.connection.logout()
            except Exception as e:
                logger.error("Error disconnecting from Yahoo: %s", e)

    def move_to_junk(self, email_id: str) -> bool:
        if not self.connection:
            if not self.connect():
                return False
        try:
            self.connection.select("INBOX")
            self.connection.copy(email_id, '"Bulk Mail"')
            self.connection.store(email_id, "+FLAGS", "\\Deleted")
            self.connection.expunge()
            return True
        except Exception as e:
            logger.error("Error moving email to Spam: %s", e)
            return False

    def fetch_emails(self, folder: str = "INBOX", limit: int = 100) -> List[Dict[str, Any]]:
        if not self.connection:
            if not self.connect():
                return []
        try:
            self.connection.select(folder)
            _, messages = self.connection.search(None, "ALL")
            email_ids = messages[0].split()
            email_ids = email_ids[-limit:] if limit else email_ids
            emails = []
            for email_id in email_ids:
                _, msg_data = self.connection.fetch(email_id, "(RFC822)")
                email_message = email.message_from_bytes(msg_data[0][1])
                emails.append(self.process_email({
                    "id": email_id.decode(),
                    "from": self._decode_header(email_message["From"]),
                    "to": self._decode_header(email_message["To"]),
                    "subject": self._decode_header(email_message["Subject"]),
                    "body": self.extract_body_text(email_message),
                    "date": email_message["Date"],
                    "folder": folder,
                    "headers": self.extract_auth_headers(email_message),
                }))
            return emails
        except Exception as e:
            logger.error("Error fetching emails from Yahoo: %s", e)
            return []

    def _decode_header(self, header: str) -> str:
        if header is None:
            return ""
        try:
            decoded_header: List[Tuple[Union[str, bytes], Optional[str]]] = decode_header(header)
            return " ".join(
                text.decode(charset or "utf-8") if isinstance(text, bytes) else text
                for text, charset in decoded_header
            )
        except Exception as e:
            logger.error("Error decoding header: %s", e)
            return str(header)
