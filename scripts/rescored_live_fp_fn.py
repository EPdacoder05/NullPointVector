#!/usr/bin/env python3
"""Lightweight live FP/FN fix — SQL-first, no mass decrypt."""
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
            # Clear Chime / Slack / Claude-class known-good still sitting ungraded
            cur.execute(
                """
                UPDATE messages
                SET label = 0, is_threat = 0, confidence = 0.02,
                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                      '{safe_domain}', '"known_good_backfill"'::jsonb)
                WHERE label IS NULL AND message_type = 'phishing'
                  AND (
                    sender ILIKE '%%@%%chime.com%%'
                    OR sender ILIKE '%%@%%slack.com%%'
                    OR sender ILIKE '%%@%%anthropic.com%%'
                    OR sender ILIKE '%%@%%claude.ai%%'
                    OR sender ILIKE '%%@%%amazon.jobs%%'
                    OR sender ILIKE '%%@%%stripe.com%%'
                    OR sender ILIKE '%%@%%notion.so%%'
                    OR sender ILIKE '%%@%%figma.com%%'
                  )
                """
            )
            cleared = cur.rowcount or 0
            # Boost free-mail recruit blasts still scored "clear"
            cur.execute(
                """
                UPDATE messages
                SET is_threat = 1, confidence = 0.91,
                    metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb),
                      '{recruit_scam}', '"free_mail_recruit_backfill"'::jsonb)
                WHERE label IS NULL AND message_type = 'phishing'
                  AND confidence < 0.85
                  AND (
                    sender ILIKE '%%@gmail.com%%'
                    OR sender ILIKE '%%@yahoo.com%%'
                    OR sender ILIKE '%%@hotmail.com%%'
                    OR sender ILIKE '%%@outlook.com%%'
                  )
                  AND (
                    subject ILIKE '%%TWIC%%'
                    OR subject ILIKE '%%applied%%'
                    OR subject ILIKE '%%SOC%%'
                    OR sender ILIKE '%%khemsara%%'
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
    print(f"cleared_known_good={cleared} boosted_recruit={boosted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
