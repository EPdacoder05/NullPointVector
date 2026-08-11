#!/usr/bin/env python3
"""Clear false quarantines for known-good domains that ingested with empty headers.

GmailDoggy previously dropped Authentication-Results → known-good never fired.
Safe to clear ungraded rows whose From-domain is on KNOWN_GOOD_DOMAINS.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from common.safe_domains import domain_is_known_good  # noqa: E402


def main() -> int:
    from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
    conn = get_conn()
    if not conn:
        print("no db")
        return 1
    cleared = 0
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, sender FROM messages
                WHERE label IS NULL AND message_type = 'phishing'
                  AND (is_threat = 1 OR confidence >= 0.5)
                ORDER BY id DESC
                LIMIT 5000
                """
            )
            rows = cur.fetchall()
            for mid, sender in rows:
                ok, reason = domain_is_known_good(sender or "")
                if not ok:
                    continue
                cur.execute(
                    """
                    UPDATE messages
                    SET label = 0, is_threat = 0, confidence = 0.02,
                        metadata = jsonb_set(
                          COALESCE(metadata, '{}'::jsonb),
                          '{review_status}', '"safe"'::jsonb
                        )
                    WHERE id = %s AND label IS NULL
                    """,
                    (mid,),
                )
                if cur.rowcount:
                    cleared += 1
                    # stamp reason
                    cur.execute(
                        """
                        UPDATE messages
                        SET metadata = jsonb_set(
                          COALESCE(metadata, '{}'::jsonb),
                          '{safe_domain}', to_jsonb(%s::text)
                        )
                        WHERE id = %s
                        """,
                        (f"{reason}+backfill_empty_headers", mid),
                    )
        conn.commit()
    except Exception as e:
        print("FAILED", e)
        conn.rollback()
        return 1
    finally:
        release_conn(conn)
    print(f"cleared {cleared} known-good false quarantines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
