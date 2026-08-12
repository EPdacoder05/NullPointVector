#!/usr/bin/env python3
"""Fail-open IPQS phone enrich → Call Directory growth.

Usage (cron / fly machine):
  python scripts/enrich_directory.py

No key → exit 0. Vendor error → skip that number. Never blocks ingest.
"""
from __future__ import annotations

import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("enrich_directory")


def _candidate_numbers(limit: int = 200) -> list[str]:
    from common.reputation.base import normalize_number
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
    except Exception as e:
        logger.warning("db import: %s", e)
        return []
    conn = get_conn()
    if not conn:
        return []
    out: list[str] = []
    seen = set()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT sender FROM messages
                WHERE message_type IN ('vishing', 'smishing')
                ORDER BY timestamp DESC
                LIMIT %s
                """,
                (max(1, min(int(limit), 500)),),
            )
            for (sender,) in cur.fetchall():
                num = normalize_number(str(sender or ""))
                if num and num.startswith("+") and num not in seen:
                    seen.add(num)
                    out.append(num)
    except Exception as e:
        logger.warning("candidate query: %s", e)
    finally:
        release_conn(conn)
    return out


def main() -> int:
    key = (os.getenv("IPQS_API_KEY") or "").strip()
    if not key:
        logger.info("IPQS_API_KEY unset — skip (fail open)")
        return 0
    from common.reputation.providers import IPQSPhoneProvider
    from common.number_reputation import upsert
    provider = IPQSPhoneProvider()
    if not provider.enabled:
        logger.info("IPQS phone provider disabled — skip")
        return 0
    numbers = _candidate_numbers()
    ok = 0
    for num in numbers:
        try:
            score = provider.lookup(num)
        except Exception as e:
            logger.warning("ipqs %s: %s", num, e)
            continue
        if score is None:
            continue
        risk = float(getattr(score, "risk", 0) or 0)
        verdict = str(getattr(score, "verdict", "") or "")
        if hasattr(verdict, "value"):
            verdict = str(verdict.value)
        if risk < 0.4:
            continue
        if upsert(num, risk=risk, verdict=verdict, source="ipqs",
                  raw=getattr(score, "raw", None) or {}):
            ok += 1
    logger.info("enriched %s / %s numbers", ok, len(numbers))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
