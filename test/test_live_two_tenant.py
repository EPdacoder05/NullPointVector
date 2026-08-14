"""Live two-tenant adversarial checks against the running Postgres.

Skips cleanly when DB is unreachable. Against the local NullPoint stack this
proves FORCE RLS + set_tenant cannot leak rows, and that account delete
harvests verified labels without touching fleet keys.
"""
from __future__ import annotations

import json
import os
import uuid

import pytest


def _db_ready() -> bool:
    try:
        from Autobot.VectorDB.NullPoint_Vector import get_conn, release_conn
        conn = get_conn()
        if not conn:
            return False
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_extension WHERE extname = 'vector'")
            ok = cur.fetchone() is not None
        release_conn(conn)
        return ok
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_LIVE_DB_TESTS", "").lower() not in ("1", "true", "yes")
    or not _db_ready(),
    reason="set RUN_LIVE_DB_TESTS=1 against Docker Postgres with pgvector",
)


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def test_two_tenant_messages_cannot_cross_read():
    from Autobot.VectorDB.NullPoint_Vector import (
        create_tables,
        get_conn,
        insert_message,
        release_conn,
    )
    from common.tenant_rls import ensure_rls, set_tenant

    alpha = _unique("tenant-alpha")
    beta = _unique("tenant-beta")
    sender = f"probe-{uuid.uuid4().hex[:8]}@evil.test"
    body = _unique("secret-body")

    conn = get_conn()
    assert conn is not None
    try:
        create_tables(conn)
        ensure_rls(conn)
        mid = insert_message(
            conn,
            message_type="phishing",
            sender=sender,
            raw_content=body,
            preprocessed_text=body,
            subject="cross-tenant probe",
            is_threat=1,
            confidence=0.91,
            metadata={"label_source": "human_grade"},
            label=1,
            account_sub=alpha,
        )
        assert mid is not None

        set_tenant(conn, beta)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM messages WHERE sender = %s", (sender,))
            assert cur.fetchone()[0] == 0
            cur.execute("SELECT COUNT(*) FROM messages WHERE id = %s", (mid,))
            assert cur.fetchone()[0] == 0

        set_tenant(conn, alpha)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM messages WHERE sender = %s", (sender,))
            assert cur.fetchone()[0] == 1
    finally:
        try:
            set_tenant(conn, bypass=True)
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM messages WHERE account_sub IN (%s, %s)",
                    (alpha, beta),
                )
            conn.commit()
        except Exception:
            conn.rollback()
        release_conn(conn)


def test_account_delete_retains_verified_training_not_fleet_keys(tmp_path, monkeypatch):
    from Autobot.VectorDB.NullPoint_Vector import (
        create_tables,
        get_conn,
        insert_message,
        release_conn,
    )
    from common import account_delete, grading
    from common.tenant_rls import ensure_rls, set_tenant
    from common.user_reports import ensure_user_reports_table

    sub = _unique("departing")
    body = _unique("verified-phish-body")
    sender = f"scam-{uuid.uuid4().hex[:6]}@phish.test"
    feedback = tmp_path / "retain-phish.jsonl"
    monkeypatch.setitem(grading._BUFFER_PATHS, "phishing", feedback)

    conn = get_conn()
    assert conn is not None
    try:
        create_tables(conn)
        ensure_rls(conn)
        ensure_user_reports_table(conn)
        mid = insert_message(
            conn,
            message_type="phishing",
            sender=sender,
            raw_content=body,
            preprocessed_text=body,
            subject="wire now",
            is_threat=1,
            confidence=0.95,
            metadata={"label_source": "human_grade"},
            label=1,
            account_sub=sub,
        )
        assert mid is not None
        set_tenant(conn, bypass=True)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO fleet_threat_keys
                    (sender_key, channel, confidence, report_count, source)
                VALUES (%s, 'phishing', 0.7, 8, 'test')
                ON CONFLICT DO NOTHING
                """,
                (f"sender:{sub}",),
            )
        conn.commit()
    finally:
        release_conn(conn)

    result = account_delete.delete_account_data(sub)
    assert result["ok"] is True, result
    assert result["retained_training"].get("phishing", 0) >= 1
    assert feedback.exists()
    lines = [json.loads(line) for line in feedback.read_text().splitlines() if line.strip()]
    assert any(row.get("source") == "retained-verified" for row in lines)
    # Local-part of sender must be redacted for remaining fleet training.
    dumped = "\n".join(json.dumps(row) for row in lines)
    assert "scam-" not in dumped
    assert "redacted@phish.test" in dumped

    conn = get_conn()
    try:
        set_tenant(conn, bypass=True)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM messages WHERE account_sub = %s", (sub,),
            )
            assert cur.fetchone()[0] == 0
            cur.execute(
                "SELECT COUNT(*) FROM fleet_threat_keys WHERE sender_key = %s",
                (f"sender:{sub}",),
            )
            assert cur.fetchone()[0] >= 1
            cur.execute(
                "DELETE FROM fleet_threat_keys WHERE sender_key = %s",
                (f"sender:{sub}",),
            )
        conn.commit()
    finally:
        release_conn(conn)
