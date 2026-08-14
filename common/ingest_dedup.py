"""Ingest dedup — durable Message-ID + content fingerprint.

API Idempotency-Key (common/idempotency.py) covers POST /analyze retries.
IMAP batch ingest never sent that header — so re-polls re-inserted the same
mail. This module is the missing piece: unique keys on messages.metadata.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional

from common.email_time import normalize_message_id, parse_email_date

logger = logging.getLogger("ingest_dedup")


def ensure_ingest_dedup_indexes(conn) -> None:
    """Mailbox-scoped partial unique indexes — race-safe across pollers.

    The former global Message-ID/fingerprint indexes collapsed the same message
    delivered to two different users. Legacy rows have NULL ownership and are
    deliberately excluded from these indexes rather than assigned heuristically.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            ALTER TABLE messages ADD COLUMN IF NOT EXISTS account_sub TEXT;
            ALTER TABLE messages ADD COLUMN IF NOT EXISTS mailbox_id BIGINT;
            ALTER TABLE messages ADD COLUMN IF NOT EXISTS provider TEXT;
            ALTER TABLE messages ADD COLUMN IF NOT EXISTS provider_uid TEXT;
            ALTER TABLE messages ADD COLUMN IF NOT EXISTS uidvalidity TEXT;
            ALTER TABLE messages ADD COLUMN IF NOT EXISTS folder TEXT;

            DROP INDEX IF EXISTS idx_messages_rfc_message_id;
            DROP INDEX IF EXISTS idx_messages_ingest_fp;

            CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_mailbox_provider_uid_v2
              ON messages (
                account_sub, mailbox_id, provider,
                (COALESCE(uidvalidity, '')), (COALESCE(folder, '')), provider_uid
              )
              WHERE account_sub IS NOT NULL AND mailbox_id IS NOT NULL
                AND COALESCE(provider, '') <> ''
                AND COALESCE(provider_uid, '') <> '';

            CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_mailbox_rfc_message_id
              ON messages (account_sub, mailbox_id, (metadata->>'rfc_message_id'))
              WHERE account_sub IS NOT NULL AND mailbox_id IS NOT NULL
                AND COALESCE(metadata->>'rfc_message_id', '') <> '';

            CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_mailbox_ingest_fp
              ON messages (account_sub, mailbox_id, (metadata->>'ingest_fp'))
              WHERE account_sub IS NOT NULL AND mailbox_id IS NOT NULL
                AND COALESCE(metadata->>'ingest_fp', '') <> '';
            """
        )
    conn.commit()


def ingest_fingerprint(*, sender: str, subject: str, body: str,
                       date_raw: Any = None, rfc_message_id: str = "") -> str:
    """Stable SHA256 for dedup when Message-ID missing or stripped."""
    mid = normalize_message_id(rfc_message_id)
    if mid:
        return hashlib.sha256(f"mid:{mid}".encode()).hexdigest()
    ts = parse_email_date(date_raw).isoformat()
    blob = "|".join([
        (sender or "").strip().lower()[:200],
        (subject or "").strip().lower()[:300],
        (body or "").strip().lower()[:2000],
        ts,
    ])
    return hashlib.sha256(blob.encode()).hexdigest()


def already_ingested(conn, *, account_sub: str, mailbox_id: int,
                     provider: str = "", provider_uid: str = "",
                     uidvalidity: str = "", folder: str = "INBOX",
                     rfc_message_id: str = "", ingest_fp: str = "") -> Optional[int]:
    """Return an existing id in exactly one owned mailbox, never globally."""
    from common.tenant_rls import require_account_sub, set_tenant

    sub = require_account_sub(account_sub)
    mid_id = int(mailbox_id)
    if mid_id <= 0:
        raise ValueError("valid mailbox_id is required")
    set_tenant(conn, sub)
    mid = normalize_message_id(rfc_message_id)
    with conn.cursor() as cur:
        if provider_uid and provider:
            cur.execute(
                """
                SELECT id FROM messages
                WHERE account_sub = %s AND mailbox_id = %s
                  AND provider = %s AND provider_uid = %s
                  AND COALESCE(uidvalidity, '') = %s
                  AND COALESCE(folder, '') = %s
                LIMIT 1
                """,
                (sub, mid_id, provider.strip().lower(), str(provider_uid),
                 str(uidvalidity or ""), str(folder or "INBOX")),
            )
            row = cur.fetchone()
            if row:
                return int(row[0])
        if mid:
            cur.execute(
                """
                SELECT id FROM messages
                WHERE account_sub = %s AND mailbox_id = %s
                  AND metadata->>'rfc_message_id' = %s
                LIMIT 1
                """,
                (sub, mid_id, mid),
            )
            row = cur.fetchone()
            if row:
                return int(row[0])
        if ingest_fp:
            cur.execute(
                """
                SELECT id FROM messages
                WHERE account_sub = %s AND mailbox_id = %s
                  AND metadata->>'ingest_fp' = %s
                LIMIT 1
                """,
                (sub, mid_id, ingest_fp),
            )
            row = cur.fetchone()
            if row:
                return int(row[0])
    return None
