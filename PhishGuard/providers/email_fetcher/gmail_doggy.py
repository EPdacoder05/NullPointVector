import imaplib
import email
from email.header import decode_header
import os
import logging
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

from .base_fetcher import EmailFetcher

logger = logging.getLogger(__name__)


class GmailDoggy(EmailFetcher):
    """Gmail email fetcher — preserves auth headers for known-good short-circuit."""

    def __init__(self):
        super().__init__()
        load_dotenv()
        self._validate_credentials()

    def _validate_credentials(self):
        self.username = os.getenv("GMAIL_USER")
        self.password = os.getenv("GMAIL_PASS")
        self._oauth_access = ""
        self._accounts = []
        if self.username and self.password:
            self._accounts.append({"email": self.username, "password": self.password, "mode": "app_password"})
        try:
            from common.mailbox_store import list_all, list_for_user, get_secret, get_oauth
            rows = list_all()
            if not rows:
                sub = (os.getenv("NULLPOINT_INGEST_SUB") or "anonymous").strip()
                rows = [{**r, "account_sub": sub} for r in list_for_user(sub)]
            seen = {(a["email"], a["mode"]) for a in self._accounts}
            for row in rows:
                if (row.get("provider") or "").lower() != "gmail":
                    continue
                sub = row.get("account_sub") or (os.getenv("NULLPOINT_INGEST_SUB") or "anonymous")
                mode = (row.get("mode") or "app_password").lower()
                email = row.get("account") or ""
                key = (email, mode)
                if not email or key in seen:
                    continue
                if mode == "oauth":
                    tok = get_oauth(sub, "gmail", email) or {}
                    if tok.get("refresh_token") or tok.get("access_token"):
                        self._accounts.append({
                            "email": email, "mode": "oauth",
                            "refresh": tok.get("refresh_token") or "",
                            "access": tok.get("access_token") or "",
                        })
                        seen.add(key)
                    continue
                secret = get_secret(sub, "gmail", email)
                if secret:
                    self._accounts.append({"email": email, "password": secret, "mode": "app_password"})
                    seen.add(key)
            if self._accounts and not self.username:
                first = self._accounts[0]
                self.username = first["email"]
                self.password = first.get("password") or ""
                self._oauth_access = first.get("access") or ""
        except Exception as e:
            logger.error("mailbox_store gmail fallback: %s", e)
        if not self._accounts and (not self.username or not (self.password or self._oauth_access)):
            raise ValueError("Gmail credentials not found in environment variables or mailbox_store")

    def _login_imap(self, account: dict) -> Optional[imaplib.IMAP4_SSL]:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        if account.get("mode") == "oauth":
            access = account.get("access") or ""
            if not access and account.get("refresh"):
                from common.oauth_email import refresh_gmail_access
                access = refresh_gmail_access(account["refresh"])
            if not access:
                mail.logout()
                return None
            auth = f"user={account['email']}\x01auth=Bearer {access}\x01\x01"
            mail.authenticate("XOAUTH2", lambda _=None: auth.encode())
            return mail
        mail.login(account["email"], account["password"])
        return mail

    def connect(self) -> bool:
        try:
            account = (self._accounts[0] if self._accounts else
                       {"email": self.username, "password": self.password, "mode": "app_password"})
            self.connection = self._login_imap(account)
            return bool(self.connection)
        except Exception as e:
            logger.error("Error connecting to Gmail: %s", e)
            self.connection = None
            return False

    def disconnect(self):
        if self.connection:
            try:
                self.connection.logout()
            except Exception as e:
                logger.error("Error disconnecting from Gmail: %s", e)

    def fetch_emails(self, folder: str = "INBOX", limit: int = 100) -> List[Dict[str, Any]]:
        accounts = self._accounts or [{
            "email": self.username, "password": self.password, "mode": "app_password",
        }]
        emails: List[Dict[str, Any]] = []
        remaining = limit or 100
        for account in accounts:
            if remaining <= 0:
                break
            conn = None
            try:
                conn = self._login_imap(account)
                if not conn:
                    continue
                conn.select(folder)
                _, messages = conn.search(None, "ALL")
                email_ids = messages[0].split()
                email_ids = email_ids[-remaining:] if remaining else email_ids
                for email_id in email_ids:
                    _, msg_data = conn.fetch(email_id, "(RFC822)")
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
                remaining = (limit or 100) - len(emails)
            except Exception as e:
                logger.error("Error fetching emails from Gmail (%s): %s", account.get("email"), e)
            finally:
                if conn:
                    try:
                        conn.logout()
                    except Exception as e:
                        logger.warning("Failed to logout IMAP connection for %s: %s", account.get("email"), e)
        return emails

    def move_to_junk(self, email_id: str) -> bool:
        if not self.connection:
            if not self.connect():
                return False
        try:
            self.connection.select("INBOX")
            self.connection.copy(email_id, "Spam")
            self.connection.store(email_id, "+FLAGS", "\\Deleted")
            self.connection.expunge()
            return True
        except Exception as e:
            logger.error("Error moving email to Spam: %s", e)
            return False

    def _decode_header(self, header: str) -> str:
        if header is None:
            return ""
        decoded_header = decode_header(header)
        return " ".join(
            text.decode(charset or "utf-8") if isinstance(text, bytes) else text
            for text, charset in decoded_header
        )
