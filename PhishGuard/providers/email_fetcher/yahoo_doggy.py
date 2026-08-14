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

    def __init__(self, *, account_sub: str = "", mailbox_id: int | None = None):
        super().__init__()
        load_dotenv()
        self._requested_sub = (account_sub or "").strip()
        self._requested_mailbox_id = mailbox_id
        self._accounts: list[dict[str, Any]] = []
        self._selected_account: dict[str, Any] | None = None
        self._validate_credentials()

    def _validate_credentials(self):
        self.username = os.getenv("YAHOO_USER")
        self.password = os.getenv("YAHOO_PASS")
        if self.username and self.password and self._requested_mailbox_id is None:
            self._accounts.append({
                "email": self.username, "password": self.password,
                "account_sub": None, "mailbox_id": None,
            })
        try:
            from common.mailbox_store import get_mailbox, get_secret, list_all
            if self._requested_mailbox_id is not None:
                exact = get_mailbox(
                    self._requested_sub, self._requested_mailbox_id, provider="yahoo",
                )
                rows = [exact] if exact else []
            else:
                rows = list_all()
            for row in rows:
                if not row:
                    continue
                if (row.get("provider") or "").lower() not in ("yahoo",):
                    continue
                sub = row.get("account_sub") or ""
                mid = row.get("id")
                if not sub or not mid:
                    continue
                secret = get_secret(sub, "yahoo", row["account"])
                if secret:
                    self._accounts.append({
                        "email": row["account"], "password": secret,
                        "account_sub": sub, "mailbox_id": int(mid),
                    })
        except Exception as e:
            logger.error("mailbox_store yahoo fallback: %s", e)
        if self._accounts:
            self.username = self._accounts[0]["email"]
            self.password = self._accounts[0]["password"]
        if not self._accounts:
            raise ValueError("Yahoo credentials not found in environment variables or mailbox_store")

    def connect(self) -> bool:
        try:
            account = self._accounts[0]
            self.connection = self._login_imap(account)
            self._selected_account = account
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

    @staticmethod
    def _login_imap(account: dict) -> imaplib.IMAP4_SSL:
        conn = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
        conn.login(account["email"], account["password"])
        return conn

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

    def move_to_junk(self, email_id: str, *, folder: str = "INBOX",
                     uidvalidity: str = "") -> bool:
        if not self.connection:
            if not self.connect():
                return False
        try:
            status, _ = self.connection.select(folder or "INBOX")
            if status != "OK" or (uidvalidity and self._uidvalidity(self.connection) != str(uidvalidity)):
                return False
            typ, _ = self.connection.uid("COPY", str(email_id), '"Bulk Mail"')
            if typ != "OK":
                return False
            self.connection.uid("STORE", str(email_id), "+FLAGS", "\\Deleted")
            self.connection.expunge()
            return True
        except Exception as e:
            logger.error("Error moving email to Spam: %s", e)
            return False

    def fetch_emails(self, folder: str = "INBOX", limit: int = 100) -> List[Dict[str, Any]]:
        emails: list[dict[str, Any]] = []
        remaining = limit or 100
        for account in self._accounts:
            if remaining <= 0:
                break
            conn = None
            try:
                conn = self._login_imap(account)
                status, _ = conn.select(folder, readonly=True)
                if status != "OK":
                    continue
                uidvalidity = self._uidvalidity(conn)
                status, messages = conn.uid("search", None, "ALL")
                if status != "OK" or not messages:
                    continue
                email_ids = messages[0].split()[-remaining:]
                for email_id in email_ids:
                    status, msg_data = conn.uid("fetch", email_id, "(RFC822)")
                    if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                        continue
                    email_message = email.message_from_bytes(msg_data[0][1])
                    provider_uid = email_id.decode() if isinstance(email_id, bytes) else str(email_id)
                    emails.append(self.process_email({
                        "id": provider_uid, "provider_uid": provider_uid,
                        "uidvalidity": uidvalidity,
                        "account_sub": account.get("account_sub"),
                        "mailbox_id": account.get("mailbox_id"),
                        "from": self._decode_header(email_message["From"]),
                        "to": self._decode_header(email_message["To"]),
                        "subject": self._decode_header(email_message["Subject"]),
                        "body": self.extract_body_text(email_message),
                        "date": email_message["Date"], "folder": folder,
                        "headers": self.extract_auth_headers(email_message),
                    }))
                remaining = (limit or 100) - len(emails)
            except Exception as e:
                logger.error("Error fetching emails from Yahoo (%s): %s", account.get("email"), e)
            finally:
                if conn:
                    try:
                        conn.logout()
                    except Exception:
                        pass
        return emails

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
