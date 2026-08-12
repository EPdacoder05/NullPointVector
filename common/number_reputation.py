"""Cached vendor phone scores for Call Directory. Fail open. Never blocks ingest."""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger("number_reputation")

_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS number_reputation (
    e164 TEXT PRIMARY KEY,
    risk REAL NOT NULL DEFAULT 0,
    verdict TEXT,
    source TEXT NOT NULL DEFAULT 'ipqs',
    raw JSONB DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ DEFAULT NOW()
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
        logger.error("ensure number_reputation: %s", e)
        try:
            conn.rollback()
        except Exception as rollback_error:
            logger.warning("ensure number_reputation rollback failed: %s", rollback_error)
        return False
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def upsert(e164: str, *, risk: float, verdict: str = "", source: str = "ipqs",
           raw: Optional[dict] = None) -> bool:
    from common.reputation.base import normalize_number
    num = normalize_number(e164 or "")
    if not num:
        return False
    ensure_table()
    conn = _conn()
    if not conn:
        return False
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO number_reputation (e164, risk, verdict, source, raw, updated_at)
                VALUES (%s, %s, %s, %s, %s::jsonb, NOW())
                ON CONFLICT (e164) DO UPDATE SET
                    risk = EXCLUDED.risk,
                    verdict = EXCLUDED.verdict,
                    source = EXCLUDED.source,
                    raw = EXCLUDED.raw,
                    updated_at = NOW()
                """,
                (num, float(risk), verdict or None, source, json.dumps(raw or {})),
            )
        conn.commit()
        return True
    except Exception as e:
        logger.error("upsert number_reputation: %s", e)
        try:
            conn.rollback()
        except Exception as rollback_error:
            logger.warning("upsert number_reputation rollback failed: %s", rollback_error)
        return False
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)


def list_hot(limit: int = 2000) -> list[dict[str, Any]]:
    ensure_table()
    conn = _conn()
    if not conn:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT e164, risk, verdict, source, updated_at
                FROM number_reputation
                WHERE risk >= 0.4
                ORDER BY risk DESC
                LIMIT %s
                """,
                (max(1, min(int(limit), 5000)),),
            )
            out = []
            for e164, risk, verdict, source, ts in cur.fetchall():
                out.append({
                    "e164": e164,
                    "risk": float(risk or 0),
                    "verdict": verdict or "",
                    "source": source or "ipqs",
                    "updated_at": ts,
                })
            return out
    except Exception as e:
        logger.error("list_hot number_reputation: %s", e)
        return []
    finally:
        from Autobot.VectorDB.NullPoint_Vector import release_conn
        release_conn(conn)
