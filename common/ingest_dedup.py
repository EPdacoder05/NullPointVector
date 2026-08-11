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
    """Partial unique indexes — race-safe across pollers."""
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_rfc_message_id
              ON messages ((metadata->>'rfc_message_id'))
              WHERE COALESCE(metadata->>'rfc_message_id', '') <> '';

            CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_ingest_fp
              ON messages ((metadata->>'ingest_fp'))
              WHERE COALESCE(metadata->>'ingest_fp', '') <> '';
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


def already_ingested(conn, *, rfc_message_id: str = "", ingest_fp: str = "") -> Optional[int]:
    """Return existing message id if this mail was already stored."""
    mid = normalize_message_id(rfc_message_id)
    with conn.cursor() as cur:
        if mid:
            cur.execute(
                """
                SELECT id FROM messages
                WHERE metadata->>'rfc_message_id' = %s
                LIMIT 1
                """,
                (mid,),
            )
            row = cur.fetchone()
            if row:
                return int(row[0])
        if ingest_fp:
            cur.execute(
                """
                SELECT id FROM messages
                WHERE metadata->>'ingest_fp' = %s
                LIMIT 1
                """,
                (ingest_fp,),
            )
            row = cur.fetchone()
            if row:
                return int(row[0])
    return None
