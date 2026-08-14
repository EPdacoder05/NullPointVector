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

    def __init__(self, *, account_sub: str = "", mailbox_id: int | None = None):
        super().__init__()
        load_dotenv()
        self._requested_sub = (account_sub or "").strip()
        self._requested_mailbox_id = mailbox_id
        self._selected_account: dict[str, Any] | None = None
        self._validate_credentials()

    def _validate_credentials(self):
        self.username = os.getenv("GMAIL_USER")
        self.password = os.getenv("GMAIL_PASS")
        self._oauth_access = ""
        self._accounts = []
        if self.username and self.password and self._requested_mailbox_id is None:
            # Legacy operator credential has no tenant/mailbox identity. The
            # ingest layer will reject its messages until it is connected in UI.
            self._accounts.append({"email": self.username, "password": self.password,
                                   "mode": "app_password", "account_sub": None,
                                   "mailbox_id": None})
        try:
            from common.mailbox_store import get_mailbox, get_oauth, get_secret, list_all
            if self._requested_mailbox_id is not None:
                exact = get_mailbox(
                    self._requested_sub, self._requested_mailbox_id, provider="gmail",
                )
                rows = [exact] if exact else []
            else:
                rows = list_all()
            seen = {
                (a.get("account_sub"), a.get("mailbox_id"), a["email"], a["mode"])
                for a in self._accounts
            }
            for row in rows:
                if not row:
                    continue
                if (row.get("provider") or "").lower() != "gmail":
                    continue
                sub = row.get("account_sub") or ""
                mailbox_id = row.get("id")
                mode = (row.get("mode") or "app_password").lower()
                email = row.get("account") or ""
                key = (sub, mailbox_id, email, mode)
                if not sub or not mailbox_id or not email or key in seen:
                    continue
                if mode == "oauth":
                    tok = get_oauth(sub, "gmail", email) or {}
                    if tok.get("refresh_token") or tok.get("access_token"):
                        self._accounts.append({
                            "email": email, "mode": "oauth",
                            "refresh": tok.get("refresh_token") or "",
                            "access": tok.get("access_token") or "",
                            "account_sub": sub, "mailbox_id": int(mailbox_id),
                        })
                        seen.add(key)
                    continue
                secret = get_secret(sub, "gmail", email)
                if secret:
                    self._accounts.append({
                        "email": email, "password": secret, "mode": "app_password",
                        "account_sub": sub, "mailbox_id": int(mailbox_id),
                    })
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
            self._selected_account = account if self.connection else None
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
                status, _ = conn.select(folder, readonly=True)
                if status != "OK":
                    continue
                uidvalidity = self._uidvalidity(conn)
                status, messages = conn.uid("search", None, "ALL")
                if status != "OK" or not messages:
                    continue
                email_ids = messages[0].split()
                email_ids = email_ids[-remaining:] if remaining else email_ids
                for email_id in email_ids:
                    status, msg_data = conn.uid("fetch", email_id, "(RFC822)")
                    if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                        continue
                    email_message = email.message_from_bytes(msg_data[0][1])
                    emails.append(self.process_email({
                        "id": email_id.decode(),
                        "provider_uid": email_id.decode(),
                        "uidvalidity": uidvalidity,
                        "account_sub": account.get("account_sub"),
                        "mailbox_id": account.get("mailbox_id"),
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

    def move_to_junk(self, email_id: str, *, folder: str = "INBOX",
                     uidvalidity: str = "") -> bool:
        if not self.connection:
            if not self.connect():
                return False
        try:
            status, _ = self.connection.select(folder or "INBOX")
            if status != "OK" or (uidvalidity and self._uidvalidity(self.connection) != str(uidvalidity)):
                return False
            typ, _ = self.connection.uid("COPY", str(email_id), "Spam")
            if typ != "OK":
                return False
            self.connection.uid("STORE", str(email_id), "+FLAGS", "\\Deleted")
            self.connection.expunge()
            return True
        except Exception as e:
            logger.error("Error moving email to Spam: %s", e)
            return False

    @staticmethod
    def _uidvalidity(conn) -> str:
        try:
            response = conn.response("UIDVALIDITY")
            values = response[1] if response and len(response) > 1 else None
            if values:
                value = values[-1]
                return value.decode() if isinstance(value, bytes) else str(value)
        except Exception:
            pass
        return ""

    def _decode_header(self, header: str) -> str:
        if header is None:
            return ""
        decoded_header = decode_header(header)
        return " ".join(
            text.decode(charset or "utf-8") if isinstance(text, bytes) else text
            for text, charset in decoded_header
        )
