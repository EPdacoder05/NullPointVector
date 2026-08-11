#!/usr/bin/env python3
"""Collapse duplicate ingest rows (same Message-ID or same sender+subject).

Keeps the oldest id; auto-grades extras as safe (label=0) so Quarantine clears.
Also clears Capital One auth-pass FPs via known-good / auth_financial path.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))


def main() -> int:
    from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn

    conn = get_conn()
    if not conn:
        print("no db")
        return 1
    collapsed = 0
    cap1 = 0
    try:
        with conn.cursor() as cur:
            # 1) Dupes with shared rfc_message_id — keep MIN(id)
            cur.execute(
                """
                WITH d AS (
                  SELECT metadata->>'rfc_message_id' AS mid, MIN(id) AS keep_id
                  FROM messages
                  WHERE COALESCE(metadata->>'rfc_message_id', '') <> ''
                  GROUP BY 1
                  HAVING COUNT(*) > 1
                )
                UPDATE messages m
                SET label = 0, is_threat = 0, confidence = LEAST(confidence, 0.05),
                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                      '{dedup}', '"collapsed_rfc_message_id"'::jsonb)
                FROM d
                WHERE m.metadata->>'rfc_message_id' = d.mid
                  AND m.id <> d.keep_id
                  AND m.label IS NULL
                """
            )
            collapsed += cur.rowcount or 0

            # 2) Same-sender flood (Avinash/Vertiv class) — subject is encrypted
            # so we cannot GROUP BY subject; collapse excess ungraded by sender.
            cur.execute(
                """
                WITH d AS (
                  SELECT sender, MIN(id) AS keep_id
                  FROM messages
                  WHERE label IS NULL
                    AND (
                      sender ILIKE '%%@vertiv.com%%'
                      OR sender ILIKE '%%Avinash.Reddy%%'
                    )
                  GROUP BY sender
                  HAVING COUNT(*) > 2
                )
                UPDATE messages m
                SET label = 0, is_threat = 0, confidence = LEAST(confidence, 0.05),
                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                      '{dedup}', '"collapsed_sender_flood"'::jsonb)
                FROM d
                WHERE m.sender = d.sender
                  AND m.id <> d.keep_id
                  AND m.label IS NULL
                """
            )
            collapsed += cur.rowcount or 0

            # 3) Capital One / bank auth-pass FPs still sitting ungraded
            cur.execute(
                """
                UPDATE messages
                SET is_threat = 0, confidence = 0.02,
                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                      '{safe_domain}', '"capitalone_auth_backfill"'::jsonb)
                WHERE label IS NULL
                  AND (
                    sender ILIKE '%%@%%capitalone.com%%'
                    OR sender ILIKE '%%capitalone@notification%%'
                  )
                """
            )
            cap1 = cur.rowcount or 0
        conn.commit()
    except Exception as e:
        print("FAILED", e)
        try:
            conn.rollback()
        except Exception:
            pass
        return 1
    finally:
        release_conn(conn)
    print(f"collapsed_dupes={collapsed} capitalone_cleared={cap1}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
