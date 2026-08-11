"""Per-account mailbox credentials (encrypted) — not shared .env."""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger("mailbox_store")

_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS user_mailboxes (
    id SERIAL PRIMARY KEY,
    account_sub TEXT NOT NULL,
    provider TEXT NOT NULL,
    account_email TEXT NOT NULL,
    secret_enc TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'app_password',
    meta JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (account_sub, provider, account_email)
);
"""


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
        logger.error("ensure user_mailboxes: %s", e)
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def _enc(text: str) -> str:
    """Fernet token as str for TEXT column (reversible — needed for IMAP)."""
    from Autobot.VectorDB.NullPoint_Vector import encrypt_data
    raw = encrypt_data(text)
    if isinstance(raw, bytes):
        return raw.decode("utf-8")
    return str(raw)


def _dec(token: str) -> str:
    from Autobot.VectorDB.NullPoint_Vector import decrypt_data
    return decrypt_data(token)


def upsert_app_password(*, account_sub: str, provider: str,
                        account_email: str, app_password: str) -> dict[str, Any]:
    ensure_table()
    conn = _conn()
    if not conn:
        return {"ok": False, "error": "db_unavailable"}
    provider = (provider or "").strip().lower()
    account_email = (account_email or "").strip()
    app_password = (app_password or "").strip()
    account_sub = (account_sub or "").strip() or "anonymous"
    if provider not in ("yahoo", "gmail", "microsoft", "outlook"):
        return {"ok": False, "error": "bad_provider"}
    if "@" not in account_email or len(app_password) < 8:
        return {"ok": False, "error": "need_email_and_app_password"}
    try:
        blob = _enc(json.dumps({"password": app_password}))
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO user_mailboxes (account_sub, provider, account_email, secret_enc, mode)
                VALUES (%s, %s, %s, %s, 'app_password')
                ON CONFLICT (account_sub, provider, account_email)
                DO UPDATE SET secret_enc = EXCLUDED.secret_enc,
                              mode = 'app_password',
                              updated_at = NOW()
                RETURNING id
                """,
                (account_sub, provider, account_email, blob),
            )
            row = cur.fetchone()
        conn.commit()
        return {"ok": True, "id": row[0] if row else None, "account": account_email, "provider": provider}
    except Exception as e:
        logger.error("upsert mailbox: %s", e)
        try:
            conn.rollback()
        except Exception:
            pass
        return {"ok": False, "error": "save_failed"}
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def list_for_user(account_sub: str) -> list[dict[str, Any]]:
    ensure_table()
    conn = _conn()
    if not conn:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, provider, account_email, mode, updated_at
                FROM user_mailboxes
                WHERE account_sub = %s
                ORDER BY updated_at DESC
                """,
                (account_sub,),
            )
            out = []
            for _id, provider, account_email, mode, updated in cur.fetchall():
                out.append({
                    "id": _id,
                    "provider": provider,
                    "account": account_email,
                    "mode": mode,
                    "updated_at": updated.isoformat() if updated else None,
                })
            return out
    except Exception as e:
        logger.error("list mailboxes: %s", e)
        return []
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def get_secret(account_sub: str, provider: str, account_email: str) -> Optional[str]:
    """Return plaintext app password for ingest (caller must not log it)."""
    conn = _conn()
    if not conn:
        return None
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT secret_enc FROM user_mailboxes
                WHERE account_sub = %s AND provider = %s AND account_email = %s
                LIMIT 1
                """,
                (account_sub, provider, account_email),
            )
            row = cur.fetchone()
        if not row:
            return None
        data = json.loads(_dec(row[0]))
        return data.get("password")
    except Exception as e:
        logger.error("get_secret: %s", e)
        return None
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)
