"""Resilience gate: a DB outage must NOT lose a confirmed threat.

Proves the durable DLQ contract end to end:
  1. DB down  → persist_threat_durable() retries, then dead-letters (depth grows).
  2. DB back  → drain_threats() replays the buffered threat into the DB (depth → 0).

Runs against the disk fallback by default (no external deps); if REDIS_URL is set
the same assertions exercise the Redis layer.
"""
import importlib
import json
import os
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _fresh_dlq(tmpdir):
    os.environ["DLQ_DIR"] = tmpdir
    # Reload so the module picks up DLQ_DIR and a clean state.
    import common.streaming.dlq as dlq
    importlib.reload(dlq)
    return dlq


def _fake_store_module(monkeypatch, store):
    module = types.ModuleType("Autobot.VectorDB.NullPoint_Vector")
    module.store_threat = store
    monkeypatch.setitem(sys.modules, "Autobot.VectorDB.NullPoint_Vector", module)
    return module


def test_no_data_loss_then_self_heal(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        dlq = _fresh_dlq(tmp)

        # --- Phase 1: DB is DOWN (store returns an error dict) ---
        nv = _fake_store_module(
            monkeypatch, lambda **kw: {"error": "connection refused"}
        )
        ok = dlq.persist_threat_durable(
            account_sub="tenant-alpha",
            content="Your bank account is locked, verify at bank-secure.ru",
            threat_type="phishing", sender="x@bank-secure.ru",
            metadata={"risk_score": 0.97, "label": 1}, retries=1, backoff=0.0)
        assert ok is False, "should report deferred persistence"
        assert dlq.depth("threat") == 1, "threat must be buffered, never dropped"

        # --- Phase 2: DB is BACK (store succeeds) → drainer replays it ---
        stored = {}
        def _ok_store(**kw):
            stored.update(kw)
            return {"id": 123, "status": "stored"}
        monkeypatch.setattr(nv, "store_threat", _ok_store)

        res = dlq.drain_threats()
        assert res["replayed"] == 1 and res["failed"] == 0, res
        assert dlq.depth("threat") == 0, "DLQ must be empty after self-heal"
        assert stored.get("threat_type") == "phishing"
        assert "bank-secure.ru" in stored.get("content", "")
        assert stored.get("account_sub") == "tenant-alpha"


def test_drain_keeps_items_while_db_still_down(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        dlq = _fresh_dlq(tmp)
        _fake_store_module(monkeypatch, lambda **kw: {"error": "still down"})

        dlq.dead_letter("threat", {"account_sub": "tenant-beta",
                                   "content": "c", "threat_type": "smishing",
                                   "sender": "s", "metadata": {}})
        assert dlq.depth("threat") == 1
        # Draining while the dependency is still down must PRESERVE the item.
        res = dlq.drain_threats()
        assert res["replayed"] == 0
        assert dlq.depth("threat") == 1, "item must be kept, not discarded"


def test_missing_tenant_cannot_be_persisted_or_dead_lettered(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        dlq = _fresh_dlq(tmp)
        calls = []
        _fake_store_module(monkeypatch, lambda **kw: calls.append(kw))
        dead_letters = []
        monkeypatch.setattr(dlq, "dead_letter", lambda *args: dead_letters.append(args))

        ok = dlq.persist_threat_durable(
            account_sub="",
            content="unowned",
            threat_type="phishing",
            sender="unknown",
            metadata={},
            retries=0,
            backoff=0.0,
        )

        assert ok is False
        assert calls == []
        assert dead_letters == []


def test_legacy_tenantless_dlq_item_cannot_replay_into_another_tenant(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        dlq = _fresh_dlq(tmp)
        calls = []
        _fake_store_module(monkeypatch, lambda **kw: calls.append(kw) or {"id": 1})
        # Simulate an entry written by the legacy implementation. The current
        # dead_letter boundary itself rejects this payload.
        legacy = {
            "content": "legacy",
            "threat_type": "phishing",
            "sender": "unknown",
            "metadata": {},
        }
        dlq._disk_path("threat").write_text(
            json.dumps(legacy) + "\n", encoding="utf-8",
        )

        result = dlq.drain_threats()

        assert result == {"replayed": 0, "failed": 1}
        assert calls == []
        assert dlq.depth("threat") == 1


def test_dead_letter_boundary_rejects_tenantless_threat():
    with tempfile.TemporaryDirectory() as tmp:
        dlq = _fresh_dlq(tmp)

        assert dlq.dead_letter("threat", {"content": "unowned"}) is False
        assert dlq.depth("threat") == 0


def test_dlq_replay_preserves_exact_tenant(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        dlq = _fresh_dlq(tmp)
        calls = []
        _fake_store_module(monkeypatch, lambda **kw: calls.append(kw) or {"id": 1})
        dlq.dead_letter("threat", {
            "account_sub": "tenant-alpha",
            "content": "owned",
            "threat_type": "smishing",
            "sender": "sender",
            "metadata": {},
        })

        result = dlq.drain_threats()

        assert result == {"replayed": 1, "failed": 0}
        assert [call["account_sub"] for call in calls] == ["tenant-alpha"]


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
