"""Account teardown — GDPR/CCPA right to deletion (personal data only).

Personal identifiers, mailbox credentials, and raw inbox content are wiped.
Verified threat labels that improve fleet detection are harvested into the
durable feedback buffers (anonymized) before message rows are deleted.
Shared fleet_threat_keys are never touched — they protect remaining users.

IMPORTANT: this module must not nest ``get_conn()`` while holding a pooled
connection (pool deadlock).
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("account_delete")

_TABLE_DELETES = (
    ("user_mailboxes", "mailboxes"),
    ("user_reports", "reports"),
    ("messages", "messages"),
    ("provider_action_queue", "provider_actions"),
    ("safe_senders", "safe_senders"),
)

_EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+)$")


def _redact_sender(sender: str | None) -> str:
    raw = (sender or "").strip().lower()
    m = _EMAIL_RE.match(raw)
    if m:
        return f"redacted@{m.group(1)}"
    if raw.startswith("+") and raw[1:].isdigit():
        return f"+{'*' * max(0, len(raw) - 5)}{raw[-4:]}"
    return "redacted"


def _harvest_verified_training(conn, account_sub: str) -> dict[str, int]:
    """Copy trusted human/vendor labels into feedback buffers, then allow delete."""
    out = {"phishing": 0, "smishing": 0, "vishing": 0}
    from Autobot.VectorDB.NullPoint_Vector import decrypt_data
    from common.grading import trusted_db_label, feedback_buffer_path
    from PhishGuard.phish_mlm.training.feedback_buffer import FeedbackBuffer

    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('public.messages')")
        if not cur.fetchone()[0]:
            return out
        cur.execute(
            """
            SELECT message_type, sender, subject, preprocessed_text, label, metadata
              FROM messages
             WHERE account_sub = %s
               AND label IS NOT NULL
            """,
            (account_sub,),
        )
        rows = cur.fetchall() or []

    for message_type, sender, enc_subject, enc_body, _label, metadata in rows:
        channel = (message_type or "phishing").strip().lower()
        path = feedback_buffer_path(channel)
        if path is None:
            continue
        meta = metadata if isinstance(metadata, dict) else {}
        if not isinstance(meta, dict):
            try:
                import json
                meta = json.loads(metadata) if isinstance(metadata, (str, bytes, memoryview)) else {}
            except Exception:
                meta = {}
        if not isinstance(meta, dict):
            meta = {}
        trusted = trusted_db_label({"label": _label, "metadata": meta})
        if trusted is None:
            continue
        try:
            subject = decrypt_data(enc_subject) if enc_subject else ""
            body = decrypt_data(enc_body) if enc_body else ""
        except Exception:
            subject, body = "", ""
        if not (body or subject):
            continue
        record = {
            "subject": (subject or "")[:300],
            "body": (body or "")[:8_000],
            "from": _redact_sender(sender),
            "sender": _redact_sender(sender),
        }
        if channel == "vishing":
            record["caller_id"] = _redact_sender(sender)
            record["transcript"] = record["body"]
        try:
            FeedbackBuffer(path).append(
                record, int(trusted), source="retained-verified",
            )
            out[channel] = out.get(channel, 0) + 1
        except Exception:
            logger.exception("retain feedback failed [%s]", channel)
    return out


def delete_account_data(account_sub: str) -> dict[str, Any]:
    """Hard-delete personal rows for this account. Never raises to callers."""
    sub = (account_sub or "").strip()
    out: dict[str, Any] = {
        "ok": False, "account_sub": sub,
        "mailboxes": 0, "reports": 0, "messages": 0,
        "provider_actions": 0, "safe_senders": 0, "provider_requests": 0,
        "deck_accounts": 0,
        "retained_training": {},
    }
    if not sub or sub in ("anon", "anonymous"):
        out["error"] = "bad_account"
        return out
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
    except Exception as e:
        out["error"] = f"db:{e}"
        return out

    # Schema ensure BEFORE taking the worker connection — nested get_conn
    # while holding a pooled conn deadlocks when minconn==maxconn.
    try:
        from common.mailbox_store import ensure_table
        ensure_table()
    except Exception:
        logger.exception("mailbox ensure before delete failed")

    conn = get_conn()
    if not conn:
        out["error"] = "db_unavailable"
        return out
    try:
        from common.tenant_rls import require_account_sub, set_tenant
        from common.user_reports import ensure_user_reports_table

        sub = require_account_sub(sub)
        ensure_user_reports_table(conn)
        set_tenant(conn, sub)
        # Harvest before deletes so remaining users keep verified threat signal.
        # fleet_threat_keys are intentionally not deleted.
        out["retained_training"] = _harvest_verified_training(conn, sub)
        with conn.cursor() as cur:
            for table, key in _TABLE_DELETES:
                cur.execute("SELECT to_regclass(%s)", (f"public.{table}",))
                if not cur.fetchone()[0]:
                    continue
                cur.execute(
                    f"DELETE FROM {table} WHERE account_sub = %s",
                    (sub,),
                )
                out[key] = cur.rowcount or 0
            cur.execute("SELECT to_regclass('public.provider_requests')")
            if cur.fetchone()[0]:
                cur.execute(
                    "DELETE FROM provider_requests WHERE account_sub = %s",
                    (sub,),
                )
                out["provider_requests"] = cur.rowcount or 0
            # deck_accounts is keyed by email (== account_sub for deck users).
            # Delete on THIS connection — never nest get_conn.
            cur.execute("SELECT to_regclass('public.deck_accounts')")
            if cur.fetchone()[0]:
                cur.execute("DELETE FROM deck_accounts WHERE email = %s", (sub,))
                out["deck_accounts"] = cur.rowcount or 0
        conn.commit()
        out["ok"] = True
    except Exception:
        logger.exception("account delete failed for %s", sub)
        try:
            conn.rollback()
        except Exception:
            pass
        out["error"] = "delete_failed"
    finally:
        release_conn(conn)
    return out
