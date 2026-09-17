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
        from common.tenant_rls import ensure_rls
        ensure_rls(conn)
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
    provider = (provider or "").strip().lower()
    account_email = (account_email or "").strip()
    app_password = (app_password or "").strip()
    from common.tenant_rls import TenantContextError, require_account_sub
    try:
        account_sub = require_account_sub(account_sub)
    except TenantContextError:
        return {"ok": False, "error": "tenant_required"}
    if provider not in ("yahoo", "gmail", "microsoft", "outlook"):
        return {"ok": False, "error": "bad_provider"}
    if "@" not in account_email or len(app_password) < 8:
        return {"ok": False, "error": "need_email_and_app_password"}
    ensure_table()
    conn = _conn()
    if not conn:
        return {"ok": False, "error": "db_unavailable"}
    try:
        from common.tenant_rls import set_tenant
        set_tenant(conn, account_sub)
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
    from common.tenant_rls import TenantContextError, require_account_sub
    try:
        account_sub = require_account_sub(account_sub)
    except TenantContextError:
        return []
    ensure_table()
    conn = _conn()
    if not conn:
        return []
    try:
        from common.tenant_rls import set_tenant
        set_tenant(conn, account_sub)
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


def operator_account_sub() -> str:
    """Tenant that owns the single-operator Yahoo mailbox on this box.

    Prefer OPERATOR_ACCOUNT_SUB. If exactly one Signal Deck account exists,
    use that email. Otherwise fall back to API_PILOT_USER / API_ADMIN_USER.
    """
    import os
    from common.tenant_rls import TenantContextError, require_account_sub

    explicit = (os.getenv("OPERATOR_ACCOUNT_SUB") or "").strip()
    if explicit:
        return require_account_sub(explicit)

    ensure_table()
    conn = _conn()
    emails: list[str] = []
    if conn:
        try:
            from common.tenant_rls import set_tenant
            set_tenant(conn, bypass=True)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 1 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'deck_accounts'
                    """
                )
                if cur.fetchone():
                    cur.execute(
                        """
                        SELECT email FROM deck_accounts
                        WHERE email IS NOT NULL AND email <> ''
                        ORDER BY created_at ASC NULLS LAST
                        LIMIT 2
                        """
                    )
                    emails = [str(r[0]).strip() for r in (cur.fetchall() or []) if r and r[0]]
        except Exception as e:
            logger.warning("operator_account_sub deck_accounts: %s", e)
        finally:
            from Autobot.VectorDB.NullPoint_Vector import release_conn
            release_conn(conn)
    if len(emails) == 1:
        return require_account_sub(emails[0])
    for key in ("API_PILOT_USER", "API_ADMIN_USER"):
        value = (os.getenv(key) or "").strip()
        if value:
            return require_account_sub(value)
    raise TenantContextError("operator tenant is not configured")


def reclaim_null_tenant_rows(account_sub: str) -> int:
    """Map legacy NULL-tenant message rows to the operator so FORCE RLS can see them."""
    from common.tenant_rls import require_account_sub, set_tenant
    sub = require_account_sub(account_sub)
    ensure_table()
    conn = _conn()
    if not conn:
        return 0
    updated = 0
    try:
        set_tenant(conn, bypass=True)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'messages'
                  AND column_name = 'account_sub'
                """
            )
            if cur.fetchone():
                cur.execute(
                    "UPDATE messages SET account_sub = %s WHERE account_sub IS NULL",
                    (sub,),
                )
                updated = cur.rowcount or 0
        conn.commit()
        if updated:
            logger.info("reclaimed %s NULL-tenant message rows for operator", updated)
        return updated
    except Exception as e:
        logger.error("reclaim_null_tenant_rows: %s", e)
        try:
            conn.rollback()
        except Exception:
            pass
        return 0
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def bootstrap_operator_env_mailboxes() -> dict[str, Any]:
    """Bind YAHOO_USER/GMAIL_USER from env onto the operator tenant mailbox row.

    Raw .env credentials without mailbox_id are discarded at ingest. This writes
    the same secrets into user_mailboxes so the monitor can persist mail.
    """
    import os
    from common.tenant_rls import TenantContextError

    try:
        sub = operator_account_sub()
    except TenantContextError as e:
        return {"ok": False, "error": str(e)}

    created: list[dict[str, Any]] = []
    yahoo_user = (os.getenv("YAHOO_USER") or "").strip()
    yahoo_pass = (os.getenv("YAHOO_PASS") or "").strip()
    if yahoo_user and yahoo_pass:
        created.append(upsert_app_password(
            account_sub=sub, provider="yahoo",
            account_email=yahoo_user, app_password=yahoo_pass,
        ))
    gmail_user = (os.getenv("GMAIL_USER") or "").strip()
    gmail_pass = (os.getenv("GMAIL_PASS") or "").strip()
    if gmail_user and gmail_pass:
        created.append(upsert_app_password(
            account_sub=sub, provider="gmail",
            account_email=gmail_user, app_password=gmail_pass,
        ))
    reclaimed = reclaim_null_tenant_rows(sub)
    ok = any(row.get("ok") for row in created) or reclaimed > 0 or bool(list_all())
    return {
        "ok": ok,
        "account_sub": sub,
        "mailboxes": created,
        "reclaimed": reclaimed,
    }


def list_all() -> list[dict[str, Any]]:
    """All saved mailboxes (ingest polls every friend, not just .env).

    Deliberate RLS bypass — ingest is operator-scoped, not a user session.
    """
    ensure_table()
    conn = _conn()
    if not conn:
        return []
    try:
        from common.tenant_rls import set_tenant
        set_tenant(conn, bypass=True)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, account_sub, provider, account_email, mode, updated_at
                FROM user_mailboxes
                ORDER BY updated_at DESC
                """
            )
            out = []
            for mailbox_id, sub, provider, account_email, mode, updated in cur.fetchall():
                out.append({
                    "id": int(mailbox_id),
                    "account_sub": sub,
                    "provider": provider,
                    "account": account_email,
                    "mode": mode,
                    "updated_at": updated.isoformat() if updated else None,
                })
            return out
    except Exception as e:
        logger.error("list_all mailboxes: %s", e)
        return []
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def upsert_oauth(*, account_sub: str, provider: str, account_email: str,
                 refresh_token: str, access_token: str = "") -> dict[str, Any]:
    provider = (provider or "").strip().lower()
    account_email = (account_email or "").strip()
    from common.tenant_rls import TenantContextError, require_account_sub
    try:
        account_sub = require_account_sub(account_sub)
    except TenantContextError:
        return {"ok": False, "error": "tenant_required"}
    if provider not in ("gmail", "microsoft", "outlook"):
        return {"ok": False, "error": "bad_provider"}
    if "@" not in account_email or not (refresh_token or "").strip():
        return {"ok": False, "error": "need_email_and_refresh"}
    ensure_table()
    conn = _conn()
    if not conn:
        return {"ok": False, "error": "db_unavailable"}
    try:
        from common.tenant_rls import set_tenant
        set_tenant(conn, account_sub)
        blob = _enc(json.dumps({
            "refresh_token": refresh_token.strip(),
            "access_token": (access_token or "").strip(),
        }))
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO user_mailboxes (account_sub, provider, account_email, secret_enc, mode)
                VALUES (%s, %s, %s, %s, 'oauth')
                ON CONFLICT (account_sub, provider, account_email)
                DO UPDATE SET secret_enc = EXCLUDED.secret_enc,
                              mode = 'oauth',
                              updated_at = NOW()
                RETURNING id
                """,
                (account_sub, provider, account_email, blob),
            )
            row = cur.fetchone()
        conn.commit()
        return {"ok": True, "id": row[0] if row else None, "account": account_email, "provider": provider}
    except Exception as e:
        logger.error("upsert oauth mailbox: %s", e)
        try:
            conn.rollback()
        except Exception as rollback_error:
            logger.warning("rollback failed in upsert_oauth: %s", rollback_error)
        return {"ok": False, "error": "save_failed"}
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def get_oauth(account_sub: str, provider: str, account_email: str) -> Optional[dict[str, str]]:
    from common.tenant_rls import TenantContextError, require_account_sub
    try:
        account_sub = require_account_sub(account_sub)
    except TenantContextError:
        return None
    ensure_table()
    conn = _conn()
    if not conn:
        return None
    try:
        from common.tenant_rls import set_tenant
        set_tenant(conn, account_sub)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT secret_enc FROM user_mailboxes
                WHERE account_sub = %s AND provider = %s AND account_email = %s
                  AND mode = 'oauth'
                LIMIT 1
                """,
                (account_sub, provider, account_email),
            )
            row = cur.fetchone()
        if not row:
            return None
        data = json.loads(_dec(row[0]))
        return {
            "refresh_token": str(data.get("refresh_token") or ""),
            "access_token": str(data.get("access_token") or ""),
        }
    except Exception as e:
        logger.error("get_oauth: %s", e)
        return None
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def get_secret(account_sub: str, provider: str, account_email: str) -> Optional[str]:
    """Return plaintext app password for ingest (caller must not log it)."""
    from common.tenant_rls import TenantContextError, require_account_sub
    try:
        account_sub = require_account_sub(account_sub)
    except TenantContextError:
        return None
    ensure_table()
    conn = _conn()
    if not conn:
        return None
    try:
        from common.tenant_rls import set_tenant
        set_tenant(conn, account_sub)
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


def get_mailbox(account_sub: str, mailbox_id: int, *, provider: str = "") -> Optional[dict[str, Any]]:
    """Return one exact mailbox descriptor without decrypting its credential.

    Provider mutations must resolve by both tenant and immutable mailbox id. An
    email address or provider alone is intentionally insufficient because users
    may connect several accounts at the same provider.
    """
    from common.tenant_rls import TenantContextError, require_account_sub
    try:
        sub = require_account_sub(account_sub)
        mid = int(mailbox_id)
    except (TenantContextError, TypeError, ValueError):
        return None
    if mid <= 0:
        return None
    ensure_table()
    conn = _conn()
    if not conn:
        return None
    try:
        from common.tenant_rls import set_tenant
        set_tenant(conn, sub)
        params: list[Any] = [sub, mid]
        clause = ""
        normalized_provider = (provider or "").strip().lower()
        if normalized_provider:
            clause = " AND provider = %s"
            params.append(normalized_provider)
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, account_sub, provider, account_email, mode, updated_at
                FROM user_mailboxes
                WHERE account_sub = %s AND id = %s{clause}
                LIMIT 1
                """,
                tuple(params),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {
            "id": int(row[0]),
            "account_sub": row[1],
            "provider": row[2],
            "account": row[3],
            "mode": row[4],
            "updated_at": row[5].isoformat() if row[5] else None,
        }
    except Exception as e:
        logger.error("get_mailbox: %s", e)
        return None
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)
