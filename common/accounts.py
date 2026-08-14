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

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s.]+\.[^@\s]{2,64}$")
_MIN_PASSWORD = 10
# Apple Hide My Email / Sign in with Apple relays are real mailboxes. Apple
# introduced additional relay domains in 2026, so identity policy must not pin
# itself to the original domain alone.
_APPLE_RELAY_DOMAINS = frozenset({
    "privaterelay.appleid.com",
    "private.icloud.com",
})
# Production signup cannot be enabled until the table and login path enforce a
# verified/pending account state. Keep this a code capability, not an env flag
# that could accidentally claim an unfinished flow exists.
_PRODUCTION_VERIFIED_ACCOUNT_STATE = False

_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS deck_accounts (
    email TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
"""


def signup_open() -> bool:
    requested = os.getenv("SIGNUP_OPEN", "false").strip().lower() in ("1", "true", "yes")
    if not requested:
        return False
    from common.config import is_production_environment
    if is_production_environment():
        verification_enabled = (
            os.getenv("EMAIL_VERIFICATION_ENABLED", "false").strip().lower()
            in ("1", "true", "yes")
        )
        return verification_enabled and _PRODUCTION_VERIFIED_ACCOUNT_STATE
    return True


def normalize_email(raw: str) -> str:
    return (raw or "").strip().lower()


def valid_email(raw: str) -> bool:
    """Shape check only. Disposable burn domains are rejected in register().

    Apple private-relay aliases always pass the same shape check as other mail.
    """
    email = normalize_email(raw)
    if not _EMAIL_RE.match(email):
        return False
    if email.rsplit("@", 1)[-1] in _APPLE_RELAY_DOMAINS:
        return True
    return True


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _check_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8") if isinstance(password_hash, str) else password_hash,
        )
    except Exception:
        return False


def _reserved_usernames() -> set[str]:
    """Full emails and local-parts of env users (admin@x.com and admin)."""
    out = {"admin", "anonymous", "anon", "root"}
    for key in ("API_ADMIN_USER", "API_PILOT_USER", "API_CUSTOMER_USER", "API_ENTERPRISE_USER"):
        val = (os.getenv(key) or "").strip().lower()
        if not val:
            continue
        out.add(val)
        out.add(val.split("@", 1)[0])
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
        from common.tenant_rls import ensure_rls
        ensure_rls(conn)
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
    from common.disposable_domains import is_disposable_email
    if is_disposable_email(email):
        return {"ok": False, "error": "disposable"}
    reserved = _reserved_usernames()
    local = email.split("@", 1)[0]
    if email in reserved or local in reserved:
        return {"ok": False, "error": "reserved"}
    if len(password) < _MIN_PASSWORD:
        return {"ok": False, "error": "short_password"}
    ensure_table()
    conn = _conn()
    if not conn:
        return {"ok": False, "error": "db_unavailable"}
    try:
        from common.tenant_rls import set_tenant
        set_tenant(conn, email)
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
        from common.tenant_rls import set_tenant
        set_tenant(conn, email)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT email, password_hash, role FROM deck_accounts WHERE email = %s",
                (email,),
            )
            row = cur.fetchone()
        if not row:
            return None
        stored_email, pw_hash, role = row
        if not _check_password(password, pw_hash):
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
    # Ensure schema without holding a pool connection (avoid nested get_conn).
    ensure_table()
    conn = _conn()
    if not conn:
        return 0
    try:
        from common.tenant_rls import set_tenant
        set_tenant(conn, email)
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
