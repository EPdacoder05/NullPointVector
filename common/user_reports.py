"""User threat reports — personal namespace + fleet promotion.

Separate from analyst triage (Block / Needs review / Mark safe).
Granny path: "Were you expecting this?" → plain-English reasons → DB.

Fleet auto-promote is score influence only (confidence cap) — nightly gate
still owns champion weights.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger("user_reports")

# Plain English → internal codes (UI never shows these)
REASON_MAP = {
    "unsolicited": "UNSOLICITED",
    "credential": "CREDENTIAL_PHISH",
    "impersonation": "IMPERSONATION",
    "pressure": "URGENCY_PRESSURE",
    "seen_before": "SEEN_BEFORE",
    "other": "OTHER",
}

FLEET_REVIEW_THRESHOLD = 3
FLEET_AUTO_THRESHOLD = 8
FLEET_CONFIDENCE_CAP = 0.75


def _sender_domain(sender: str) -> str:
    m = re.search(r"@([A-Za-z0-9.\-]+)", sender or "")
    return (m.group(1) if m else "").lower().rstrip(".")


def ensure_user_reports_table(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS user_reports (
                id BIGSERIAL PRIMARY KEY,
                message_id BIGINT,
                account_sub TEXT NOT NULL DEFAULT 'anon',
                channel TEXT NOT NULL DEFAULT 'email',
                sender TEXT,
                sender_key TEXT,
                expected BOOLEAN,
                reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
                detail TEXT,
                namespace TEXT NOT NULL DEFAULT 'user',
                promoted_to_fleet BOOLEAN NOT NULL DEFAULT FALSE,
                fleet_promoted_at TIMESTAMPTZ,
                analyst_reviewed BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_user_reports_sender_key
              ON user_reports (sender_key, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_user_reports_account
              ON user_reports (account_sub, created_at DESC);

            CREATE TABLE IF NOT EXISTS fleet_threat_keys (
                sender_key TEXT PRIMARY KEY,
                channel TEXT NOT NULL DEFAULT 'email',
                confidence FLOAT NOT NULL DEFAULT 0.75,
                report_count INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL DEFAULT 'user_reports',
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            """
        )
    conn.commit()


def submit_user_report(
    *,
    message_id: Optional[int],
    account_sub: str,
    channel: str,
    sender: str,
    expected: Optional[bool],
    reasons: list,
    detail: Optional[str] = None,
) -> dict[str, Any]:
    """Persist report + maybe flag/promote fleet. Never raises to UI."""
    out: dict[str, Any] = {"ok": False, "id": None, "fleet": None}
    ch = (channel or "email").lower()
    if ch not in ("email", "sms", "call", "phishing", "smishing", "vishing"):
        ch = "email"
    if ch == "phishing":
        ch = "email"
    if ch == "smishing":
        ch = "sms"
    if ch == "vishing":
        ch = "call"

    raw_reasons = [str(r).strip().lower() for r in (reasons or []) if str(r).strip()]
    codes = [REASON_MAP.get(r, r.upper()) for r in raw_reasons]
    if not codes and expected is None and not (detail or "").strip():
        out["error"] = "empty_report"
        return out

    sender_key = _sender_domain(sender) or (sender or "").strip().lower()[:120]
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
    except Exception as e:
        out["error"] = str(e)
        return out

    conn = get_conn()
    if not conn:
        out["error"] = "no_db"
        return out
    try:
        ensure_user_reports_table(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO user_reports
                  (message_id, account_sub, channel, sender, sender_key,
                   expected, reasons, detail, namespace)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, 'user')
                RETURNING id
                """,
                (
                    int(message_id) if message_id else None,
                    (account_sub or "anon")[:128],
                    ch,
                    (sender or "")[:500],
                    sender_key,
                    expected,
                    json.dumps(codes),
                    (detail or "").strip()[:400] or None,
                ),
            )
            rid = cur.fetchone()[0]
        conn.commit()
        out["ok"] = True
        out["id"] = int(rid)
        out["fleet"] = check_fleet_promotion(conn, sender_key=sender_key, channel=ch)
    except Exception as e:
        logger.warning("submit_user_report failed: %s", e)
        out["error"] = "persist_failed"
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        release_conn(conn)
    return out


def check_fleet_promotion(conn, *, sender_key: str, channel: str = "email") -> dict[str, Any]:
    """Distinct reporters in 30d → review flag or auto fleet key (capped conf)."""
    result = {"status": "none", "count": 0, "sender_key": sender_key}
    if not sender_key:
        return result
    since = datetime.now(timezone.utc) - timedelta(days=30)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(DISTINCT account_sub)
                FROM user_reports
                WHERE sender_key = %s
                  AND expected IS FALSE
                  AND created_at >= %s
                """,
                (sender_key, since),
            )
            count = int((cur.fetchone() or [0])[0] or 0)
            result["count"] = count

            if count >= FLEET_AUTO_THRESHOLD:
                cur.execute(
                    """
                    INSERT INTO fleet_threat_keys (sender_key, channel, confidence, report_count, source)
                    VALUES (%s, %s, %s, %s, 'user_reports')
                    ON CONFLICT (sender_key) DO UPDATE SET
                      confidence = LEAST(EXCLUDED.confidence, fleet_threat_keys.confidence),
                      report_count = EXCLUDED.report_count,
                      updated_at = NOW()
                    """,
                    (sender_key, channel, FLEET_CONFIDENCE_CAP, count),
                )
                cur.execute(
                    """
                    UPDATE user_reports
                    SET promoted_to_fleet = TRUE, fleet_promoted_at = NOW()
                    WHERE sender_key = %s AND promoted_to_fleet = FALSE
                    """,
                    (sender_key,),
                )
                result["status"] = "auto_promoted"
            elif count >= FLEET_REVIEW_THRESHOLD:
                result["status"] = "analyst_review"
            else:
                result["status"] = "recorded"
        conn.commit()
    except Exception as e:
        logger.warning("fleet promotion check failed: %s", e)
        try:
            conn.rollback()
        except Exception:
            pass
        result["status"] = "error"
    return result


def is_fleet_blocked_sender(sender: str) -> tuple[bool, float]:
    """Lookup shared fleet key — fail-open on DB errors."""
    key = _sender_domain(sender) or (sender or "").strip().lower()
    if not key:
        return False, 0.0
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
        conn = get_conn()
        if not conn:
            return False, 0.0
        try:
            ensure_user_reports_table(conn)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT confidence FROM fleet_threat_keys WHERE sender_key = %s",
                    (key,),
                )
                row = cur.fetchone()
                if row:
                    return True, float(row[0] or FLEET_CONFIDENCE_CAP)
            return False, 0.0
        finally:
            release_conn(conn)
    except Exception:
        return False, 0.0
