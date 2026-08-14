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
    def __init__(self, *, account_sub: str = "", mailbox_id: int | None = None):
        super().__init__()
        load_dotenv()
        self._requested_sub = (account_sub or "").strip()
        self._requested_mailbox_id = mailbox_id
        self.email = os.getenv("OUTLOOK_EMAIL") or os.getenv("MICROSOFT_EMAIL")
        self.password = os.getenv("OUTLOOK_PASSWORD") or os.getenv("MICROSOFT_PASSWORD")
        self.imap_server = "outlook.office365.com"
        self.imap_port = 993
        self._accounts: list[dict[str, Any]] = []
        self._selected_account: dict[str, Any] | None = None
        if self.email and self.password and self._requested_mailbox_id is None:
            self._accounts.append({
                "email": self.email, "password": self.password, "mode": "app_password",
                "account_sub": None, "mailbox_id": None,
            })
        try:
            from common.mailbox_store import get_mailbox, get_oauth, get_secret, list_all
            if self._requested_mailbox_id is not None:
                exact = get_mailbox(self._requested_sub, self._requested_mailbox_id)
                rows = [exact] if exact else []
            else:
                rows = list_all()
            for row in rows:
                if not row or (row.get("provider") or "").lower() not in ("microsoft", "outlook"):
                    continue
                sub = row.get("account_sub") or ""
                mid = row.get("id")
                account_email = row.get("account") or ""
                mode = (row.get("mode") or "app_password").lower()
                if not sub or not mid or not account_email:
                    continue
                if mode == "oauth":
                    token = get_oauth(sub, row["provider"], account_email) or {}
                    if token.get("refresh_token") or token.get("access_token"):
                        self._accounts.append({
                            "email": account_email, "mode": "oauth",
                            "refresh": token.get("refresh_token") or "",
                            "access": token.get("access_token") or "",
                            "account_sub": sub, "mailbox_id": int(mid),
                        })
                else:
                    secret = get_secret(sub, row["provider"], account_email)
                    if secret:
                        self._accounts.append({
                            "email": account_email, "password": secret,
                            "mode": "app_password", "account_sub": sub,
                            "mailbox_id": int(mid),
                        })
        except Exception as e:
            logger.error("mailbox_store outlook fallback: %s", e)
        if self._accounts:
            self.email = self._accounts[0]["email"]
            self.password = self._accounts[0].get("password") or ""

    def _login_imap(self, account: dict) -> Optional[imaplib.IMAP4_SSL]:
        conn = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
        if account.get("mode") == "oauth":
            access = account.get("access") or ""
            if not access and account.get("refresh"):
                from common.oauth_email import refresh_microsoft_access
                access = refresh_microsoft_access(account["refresh"])
            if not access:
                conn.logout()
                return None
            auth = f"user={account['email']}\x01auth=Bearer {access}\x01\x01"
            conn.authenticate("XOAUTH2", lambda _=None: auth.encode())
            return conn
        conn.login(account["email"], account["password"])
        return conn

    def connect(self) -> bool:
        try:
            if not self._accounts:
                return False
            account = self._accounts[0]
            self.connection = self._login_imap(account)
            self._selected_account = account if self.connection else None
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
        email_list: List[Dict[str, Any]] = []
        remaining = limit or 100
        for account in self._accounts:
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
                status, message_numbers = conn.uid("search", None, "ALL")
                if status != "OK" or not message_numbers:
                    continue
                for num in message_numbers[0].split()[-remaining:]:
                    status, msg_data = conn.uid("fetch", num, "(RFC822)")
                    if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                        continue
                    email_body = msg_data[0][1]
                    email_message = email.message_from_bytes(email_body)
                    body = self.extract_body_text(email_message)
                    if not body:
                        body = self._plain_body(email_message)
                    provider_uid = num.decode() if isinstance(num, bytes) else str(num)
                    email_list.append(self.process_email({
                        "id": provider_uid, "provider_uid": provider_uid,
                        "uidvalidity": uidvalidity,
                        "account_sub": account.get("account_sub"),
                        "mailbox_id": account.get("mailbox_id"),
                        "subject": self._decode_header(email_message["subject"]),
                        "from": self._decode_header(email_message["from"]),
                        "to": self._decode_header(email_message["to"]),
                        "date": email_message["date"], "body": body,
                        "folder": folder,
                        "headers": self.extract_auth_headers(email_message),
                    }))
                remaining = (limit or 100) - len(email_list)
            except Exception as e:
                logger.error("Error fetching Outlook emails (%s): %s", account.get("email"), e)
            finally:
                if conn:
                    try:
                        conn.logout()
                    except Exception:
                        pass
        return email_list

    def move_to_junk(self, email_id: str, *, folder: str = "INBOX",
                     uidvalidity: str = "") -> bool:
        if not self.connection and not self.connect():
            return False
        try:
            status, _ = self.connection.select(folder or "INBOX")
            if status != "OK" or (uidvalidity and self._uidvalidity(self.connection) != str(uidvalidity)):
                return False
            # Outlook junk folder name varies; try common labels.
            for junk in ("Junk", "Junk Email", "Spam"):
                try:
                    typ, _ = self.connection.uid("COPY", str(email_id), junk)
                    if typ == "OK":
                        self.connection.uid("STORE", str(email_id), "+FLAGS", "\\Deleted")
                        self.connection.expunge()
                        return True
                except Exception:
                    continue
            return False
        except Exception as e:
            logger.error("Outlook move_to_junk failed: %s", e)
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
