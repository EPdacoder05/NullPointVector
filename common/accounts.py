"""DB-backed Signal Deck accounts (email + password hash).

Env JWT users (API_ADMIN_* / API_PILOT_*) still work. Friends sign up here.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional

import bcrypt

logger = logging.getLogger("accounts")

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s.]+\.[^@\s]{2,24}$")
_MIN_PASSWORD = 10

_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS deck_accounts (
    email TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
"""


def signup_open() -> bool:
    return os.getenv("SIGNUP_OPEN", "false").strip().lower() in ("1", "true", "yes")


def normalize_email(raw: str) -> str:
    return (raw or "").strip().lower()


def valid_email(raw: str) -> bool:
    return bool(_EMAIL_RE.match(normalize_email(raw)))


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _reserved_usernames() -> set[str]:
    out = {"admin", "anonymous", "anon", "root"}
    for key in ("API_ADMIN_USER", "API_PILOT_USER", "API_CUSTOMER_USER", "API_ENTERPRISE_USER"):
        val = (os.getenv(key) or "").strip().lower()
        if val:
            out.add(val)
    return out


def _conn():
    from Autobot.VectorDB.NullPoint_Vector import get_conn
    return get_conn()


def ensure_table() -> bool:
    conn = _conn()
    if not conn:
        return False
    try:
        with conn.cursor() as cur:
            cur.execute(_TABLE_SQL)
        conn.commit()
        return True
    except Exception as e:
        logger.error("ensure deck_accounts: %s", e)
        try:
            conn.rollback()
        except Exception as rollback_error:
            logger.warning("rollback failed in ensure_table: %s", rollback_error, exc_info=True)
        return False
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def register(email: str, password: str) -> dict[str, Any]:
    """Create a customer account. Never raises."""
    if not signup_open():
        return {"ok": False, "error": "signup_closed"}
    email = normalize_email(email)
    password = password or ""
    if not valid_email(email):
        return {"ok": False, "error": "bad_email"}
    if email in _reserved_usernames():
        return {"ok": False, "error": "reserved"}
    if len(password) < _MIN_PASSWORD:
        return {"ok": False, "error": "short_password"}
    ensure_table()
    conn = _conn()
    if not conn:
        return {"ok": False, "error": "db_unavailable"}
    try:
        pw_hash = _hash_password(password)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO deck_accounts (email, password_hash, role)
                VALUES (%s, %s, 'customer')
                ON CONFLICT (email) DO NOTHING
                RETURNING email
                """,
                (email, pw_hash),
            )
            row = cur.fetchone()
        conn.commit()
        if not row:
            return {"ok": False, "error": "email_taken"}
        return {"ok": True, "sub": email, "role": "customer"}
    except Exception as e:
        logger.error("register failed: %s", e)
        try:
            conn.rollback()
        except Exception as rollback_error:
            logger.warning("register rollback failed: %s", rollback_error)
        return {"ok": False, "error": "save_failed"}
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def verify_login(email: str, password: str) -> Optional[dict[str, str]]:
    email = normalize_email(email)
    if not email or not password:
        return None
    ensure_table()
    conn = _conn()
    if not conn:
        return None
    try:
        from common.auth import verify_password
        with conn.cursor() as cur:
            cur.execute(
                "SELECT email, password_hash, role FROM deck_accounts WHERE email = %s",
                (email,),
            )
            row = cur.fetchone()
        if not row:
            return None
        stored_email, pw_hash, role = row
        if not verify_password(password, pw_hash):
            return None
        return {"sub": stored_email, "role": role or "customer"}
    except Exception as e:
        logger.error("verify_login: %s", e)
        return None
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def delete_account(email: str) -> int:
    email = normalize_email(email)
    if not email:
        return 0
    conn = _conn()
    if not conn:
        return 0
    try:
        ensure_table()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM deck_accounts WHERE email = %s", (email,))
            n = cur.rowcount or 0
        conn.commit()
        return n
    except Exception as e:
        logger.error("delete_account: %s", e)
        try:
            conn.rollback()
        except Exception as rollback_error:
            logger.warning("delete_account rollback failed: %s", rollback_error)
        return 0
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)
