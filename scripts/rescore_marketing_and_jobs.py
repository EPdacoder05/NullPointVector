#!/usr/bin/env python3
"""SQL-light rescore: TLDR/newsletter FPs out of Quarantine; talentemail job FNs up.

No mass decrypt — sender/subject ILIKE only. Graded rows untouched.
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
    cleared = boosted = 0
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE messages
                SET is_threat = 0, confidence = 0.12,
                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                      '{marketing_mail}', '"newsletter_backfill"'::jsonb)
                WHERE label IS NULL AND message_type = 'phishing'
                  AND (
                    sender ILIKE '%%@%%tldrnewsletter.com%%'
                    OR sender ILIKE '%%tldrnewsletter.com%%'
                    OR sender ILIKE '%%@%%strawberry.me%%'
                    OR sender ILIKE '%%@%%krogermail.com%%'
                    OR sender ILIKE '%%@%%kroger.com%%'
                  )
                """
            )
            cleared = cur.rowcount or 0

            cur.execute(
                """
                UPDATE messages
                SET is_threat = 1, confidence = 0.94,
                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                      '{job_scam}', '"merge_tag_backfill"'::jsonb)
                WHERE label IS NULL AND message_type = 'phishing'
                  AND (
                    sender ILIKE '%%@talentemail.com%%'
                    OR sender ILIKE '%%talentemail.com%%'
                    OR subject ILIKE '%%[[CANDIDATEEMAIL]]%%'
                    OR subject ILIKE '%%Cloud performance Engineer%%'
                  )
                """
            )
            boosted = cur.rowcount or 0
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
    print(f"cleared_newsletter={cleared} boosted_job_scam={boosted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
