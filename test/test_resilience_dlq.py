"""Resilience gate: a DB outage must NOT lose a confirmed threat.

Proves the durable DLQ contract end to end:
  1. DB down  → persist_threat_durable() retries, then dead-letters (depth grows).
  2. DB back  → drain_threats() replays the buffered threat into the DB (depth → 0).

Runs against the disk fallback by default (no external deps); if REDIS_URL is set
the same assertions exercise the Redis layer.
"""
import importlib
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _fresh_dlq(tmpdir):
    os.environ["DLQ_DIR"] = tmpdir
    # Reload so the module picks up DLQ_DIR and a clean state.
    import common.streaming.dlq as dlq
    importlib.reload(dlq)
    return dlq


def test_no_data_loss_then_self_heal(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        dlq = _fresh_dlq(tmp)
        import Autobot.VectorDB.NullPoint_Vector as nv

        # --- Phase 1: DB is DOWN (store returns an error dict) ---
        monkeypatch.setattr(nv, "store_threat",
                            lambda **kw: {"error": "connection refused"})
        ok = dlq.persist_threat_durable(
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


def test_drain_keeps_items_while_db_still_down(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        dlq = _fresh_dlq(tmp)
        import Autobot.VectorDB.NullPoint_Vector as nv
        monkeypatch.setattr(nv, "store_threat", lambda **kw: {"error": "still down"})

        dlq.dead_letter("threat", {"content": "c", "threat_type": "smishing",
                                   "sender": "s", "metadata": {}})
        assert dlq.depth("threat") == 1
        # Draining while the dependency is still down must PRESERVE the item.
        res = dlq.drain_threats()
        assert res["replayed"] == 0
        assert dlq.depth("threat") == 1, "item must be kept, not discarded"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
