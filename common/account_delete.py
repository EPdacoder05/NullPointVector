"""Account teardown — GDPR/CCPA right to deletion (personal data only).

Env JWT users cannot be removed from process memory; we wipe everything
namespaced by account_sub and clear the session cookie on the console.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("account_delete")


def delete_account_data(account_sub: str) -> dict[str, Any]:
    """Hard-delete personal rows for this account. Never raises to callers."""
    sub = (account_sub or "").strip()
    out: dict[str, Any] = {
        "ok": False, "account_sub": sub,
        "mailboxes": 0, "reports": 0, "provider_requests": 0,
    }
    if not sub or sub in ("anon", "anonymous"):
        out["error"] = "bad_account"
        return out
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
    except Exception as e:
        out["error"] = f"db:{e}"
        return out
    conn = get_conn()
    if not conn:
        out["error"] = "db_unavailable"
        return out
    try:
        from common.mailbox_store import ensure_table
        ensure_table()
        from common.user_reports import ensure_user_reports_table
        ensure_user_reports_table(conn)
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM user_mailboxes WHERE account_sub = %s",
                (sub,),
            )
            out["mailboxes"] = cur.rowcount or 0
            cur.execute(
                "DELETE FROM user_reports WHERE account_sub = %s",
                (sub,),
            )
            out["reports"] = cur.rowcount or 0
        try:
            from common.accounts import delete_account as _delete_deck
            out["deck_accounts"] = _delete_deck(sub)
        except Exception:
            out["deck_accounts"] = 0
        with conn.cursor() as cur:
            # Optional table from provider-request form
            cur.execute(
                """
                SELECT to_regclass('public.provider_requests')
                """
            )
            if cur.fetchone()[0]:
                cur.execute(
                    "DELETE FROM provider_requests WHERE account_sub = %s",
                    (sub,),
                )
                out["provider_requests"] = cur.rowcount or 0
        conn.commit()
        out["ok"] = True
    except Exception as e:
        logger.exception("account delete failed for %s", sub)
        try:
            conn.rollback()
        except Exception:
            pass
        out["error"] = "delete_failed"
    finally:
        release_conn(conn)
    return out
