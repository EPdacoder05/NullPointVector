"""Outlook / Microsoft IMAP fetcher — same auth-header path as Yahoo/Gmail."""
from __future__ import annotations

import email
import imaplib
import logging
import os
from email.header import decode_header
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

from .base_fetcher import EmailFetcher

logger = logging.getLogger(__name__)


class OutlookDoggy(EmailFetcher):
    def __init__(self):
        super().__init__()
        load_dotenv()
        self.email = os.getenv("OUTLOOK_EMAIL") or os.getenv("MICROSOFT_EMAIL")
        self.password = os.getenv("OUTLOOK_PASSWORD") or os.getenv("MICROSOFT_PASSWORD")
        self.imap_server = "outlook.office365.com"
        self.imap_port = 993
        if not self.email or not self.password:
            try:
                from common.mailbox_store import list_all, list_for_user, get_secret
                rows = list_all()
                if not rows:
                    sub = (os.getenv("NULLPOINT_INGEST_SUB") or "anonymous").strip()
                    rows = [{**r, "account_sub": sub} for r in list_for_user(sub)]
                for row in rows:
                    if (row.get("provider") or "").lower() not in ("microsoft", "outlook"):
                        continue
                    secret = get_secret(row.get("account_sub") or "anonymous", row["provider"], row["account"])
                    if secret:
                        self.email = row["account"]
                        self.password = secret
                        break
            except Exception as e:
                logger.error("mailbox_store outlook fallback: %s", e)

    def connect(self) -> bool:
        try:
            self.connection = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            self.connection.login(self.email, self.password)
            return True
        except Exception as e:
            logger.error("Failed to connect to Outlook: %s", e)
            self.connection = None
            return False

    def disconnect(self):
        if not self.connection:
            return
        try:
            self.connection.close()
        except Exception:
            pass
        try:
            self.connection.logout()
        except Exception:
            pass
        self.connection = None

    def fetch_emails(self, folder: str = "INBOX", limit: int = 100) -> List[Dict[str, Any]]:
        if not self.connection and not self.connect():
            return []
        try:
            self.connection.select(folder)
            _, message_numbers = self.connection.search(None, "ALL")
            email_list: List[Dict[str, Any]] = []
            for num in message_numbers[0].split()[-limit:]:
                _, msg_data = self.connection.fetch(num, "(RFC822)")
                email_body = msg_data[0][1]
                email_message = email.message_from_bytes(email_body)
                subject = self._decode_header(email_message["subject"])
                from_addr = self._decode_header(email_message["from"])
                date = email_message["date"]
                body = self.extract_body_text(email_message) if hasattr(self, "extract_body_text") else ""
                if not body:
                    body = self._plain_body(email_message)
                email_list.append({
                    "subject": subject,
                    "from": from_addr,
                    "date": date,
                    "body": body,
                    "raw_email": email_body,
                    "headers": self.extract_auth_headers(email_message),
                    "imap_id": num.decode() if isinstance(num, bytes) else str(num),
                })
            return email_list
        except Exception as e:
            logger.error("Error fetching Outlook emails: %s", e)
            return []

    def move_to_junk(self, email_id: str) -> bool:
        if not self.connection and not self.connect():
            return False
        try:
            # Outlook junk folder name varies; try common labels
            for junk in ("Junk", "Junk Email", "Spam"):
                try:
                    typ, _ = self.connection.copy(email_id, junk)
                    if typ == "OK":
                        self.connection.store(email_id, "+FLAGS", "\\Deleted")
                        self.connection.expunge()
                        return True
                except Exception:
                    continue
            return False
        except Exception as e:
            logger.error("Outlook move_to_junk failed: %s", e)
            return False

    def _plain_body(self, email_message) -> str:
        try:
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain":
                        raw = part.get_payload(decode=True)
                        return (raw or b"").decode(errors="replace")
            raw = email_message.get_payload(decode=True)
            return (raw or b"").decode(errors="replace")
        except Exception:
            return ""

    def _decode_header(self, header: Optional[str]) -> str:
        if header is None:
            return ""
        decoded = decode_header(header)
        parts = []
        for value, charset in decoded:
            if isinstance(value, bytes):
                parts.append(value.decode(charset or "utf-8", errors="replace"))
            else:
                parts.append(str(value))
        return "".join(parts)
