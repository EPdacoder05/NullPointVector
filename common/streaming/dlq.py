"""
Durable dead-letter queue (DLQ) — guarantees a confirmed threat is never lost
when a downstream dependency (Postgres/PgBouncer) is momentarily down.

Layered durability (defence in depth):
  1. Redis list  ``dlq:{kind}``           — survives app restart, shared across replicas.
  2. Disk JSONL  ``data/dlq/{kind}.jsonl`` — survives even if Redis is ALSO down.

A background drainer replays entries into the real sink once the dependency
recovers, so the pipeline self-heals with **no data loss and no silent drops**.

Why both layers: Redis gives fast, shared, replica-safe buffering; the disk
fallback is the floor that holds when Redis itself is unreachable. The disk file
lives on a named volume (``app_ingestion``-style) so it outlives the container.

Complexity: enqueue O(1); drain O(k) for k pending items, capped by ``max_items``.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

_DLQ_DIR = Path(os.getenv("DLQ_DIR", "data/dlq"))
_disk_lock = threading.Lock()


def _disk_path(kind: str) -> Path:
    _DLQ_DIR.mkdir(parents=True, exist_ok=True)
    return _DLQ_DIR / f"{kind}.jsonl"


# ------------------------------------------------------------------ enqueue
def dead_letter(kind: str, payload: dict) -> None:
    """Append ``payload`` to the DLQ. NEVER raises — this is the last line of
    defence, so a failure here only logs (we cannot afford to crash the worker)."""
    line = json.dumps(payload, default=str)
    try:
        from common.redis_client import get_redis
        r = get_redis()
        if r is not None:
            r.rpush(f"dlq:{kind}", line)
            return
    except Exception as e:  # redis flaky → fall through to disk
        logger.warning("DLQ redis push failed (%s); using disk fallback", e)
    try:
        with _disk_lock, _disk_path(kind).open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception as e:
        # Truly nowhere to put it: log loudly with a truncated payload so it is
        # at least recoverable from logs. Should be effectively impossible.
        logger.error("DLQ disk write failed for %s: %s — payload=%s", kind, e, line[:200])


def depth(kind: str) -> int:
    """Pending count across both layers (best-effort; for /metrics + health)."""
    n = 0
    try:
        from common.redis_client import get_redis
        r = get_redis()
        if r is not None:
            n += int(r.llen(f"dlq:{kind}"))
    except Exception:
        pass
    try:
        p = _disk_path(kind)
        if p.exists():
            with p.open(encoding="utf-8") as fh:
                n += sum(1 for ln in fh if ln.strip())
    except Exception:
        pass
    return n


# ------------------------------------------------------------------ drain / replay
def drain(kind: str, sink: Callable[[dict], bool], max_items: int = 500) -> dict:
    """Replay DLQ entries into ``sink`` (returns True on success).

    On the first failure we STOP and keep the remaining items — the dependency
    is presumably still down, so retrying the rest now would just churn. Failed
    items are preserved (re-queued / kept on disk), never discarded.
    """
    replayed = 0
    failed = 0

    # --- Redis layer ---
    try:
        from common.redis_client import get_redis
        r = get_redis()
        if r is not None:
            key = f"dlq:{kind}"
            for _ in range(max_items):
                line = r.lpop(key)
                if line is None:
                    break
                try:
                    ok = bool(sink(json.loads(line)))
                except Exception as e:
                    ok = False
                    logger.warning("DLQ[%s] replay sink error: %s", kind, e)
                if ok:
                    replayed += 1
                else:
                    failed += 1
                    r.rpush(key, line)  # put back at the tail, stop early
                    break
    except Exception as e:
        logger.warning("DLQ[%s] redis drain failed: %s", kind, e)

    # --- Disk layer (only attempt if we did not just fail on redis) ---
    if failed == 0:
        try:
            p = _disk_path(kind)
            if p.exists():
                with _disk_lock:
                    lines = [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
                    remaining: list[str] = []
                    stopped = False
                    for i, line in enumerate(lines):
                        if stopped or replayed >= max_items:
                            remaining.append(line)
                            continue
                        try:
                            ok = bool(sink(json.loads(line)))
                        except Exception as e:
                            ok = False
                            logger.warning("DLQ[%s] disk replay error: %s", kind, e)
                        if ok:
                            replayed += 1
                        else:
                            failed += 1
                            remaining.append(line)
                            stopped = True  # dependency still down
                    # Rewrite the file with only what is left (atomic-ish).
                    if remaining:
                        p.write_text("\n".join(remaining) + "\n", encoding="utf-8")
                    else:
                        p.unlink(missing_ok=True)
        except Exception as e:
            logger.warning("DLQ[%s] disk drain failed: %s", kind, e)

    return {"replayed": replayed, "failed": failed}


# ------------------------------------------------------------------ threat helpers
def persist_threat_durable(*, content: str, threat_type: str, sender: str,
                           metadata: dict, retries: int = 2, backoff: float = 0.2) -> bool:
    """Store a confirmed threat with bounded retry; dead-letter on exhaustion.

    Returns True if persisted, False if dead-lettered (still durable, just deferred).
    Never raises — safe to call from a background task or stream worker.
    """
    last = None
    for attempt in range(retries + 1):
        try:
            from Autobot.VectorDB.NullPoint_Vector import store_threat
            res = store_threat(content=content, threat_type=threat_type,
                               sender=sender, metadata=metadata)
            if isinstance(res, dict) and not res.get("error"):
                return True
            last = res
        except Exception as e:
            last = {"error": str(e)}
        time.sleep(backoff * (attempt + 1))
    dead_letter("threat", {"content": content, "threat_type": threat_type,
                           "sender": sender, "metadata": metadata})
    logger.warning("threat persist failed after %d tries (%s) → dead-lettered",
                   retries + 1, last)
    return False


def _threat_sink(payload: dict) -> bool:
    from Autobot.VectorDB.NullPoint_Vector import store_threat
    res = store_threat(content=payload.get("content", ""),
                       threat_type=payload.get("threat_type", "phishing"),
                       sender=payload.get("sender", "unknown"),
                       metadata=payload.get("metadata") or {})
    return isinstance(res, dict) and not res.get("error")


def drain_threats(max_items: int = 500) -> dict:
    return drain("threat", _threat_sink, max_items=max_items)


def start_dlq_drainer(kind: str = "threat", interval: float = 30.0) -> threading.Thread:
    """Background self-healer: periodically flush the DLQ once the DB is back."""
    def _loop():
        while True:
            time.sleep(interval)
            try:
                if depth(kind):
                    res = drain(kind, _threat_sink)
                    if res["replayed"]:
                        logger.info("DLQ[%s] self-healed: replayed=%d failed=%d",
                                    kind, res["replayed"], res["failed"])
            except Exception as e:
                logger.error("DLQ[%s] drainer loop error: %s", kind, e)

    t = threading.Thread(target=_loop, name=f"dlq-drainer-{kind}", daemon=True)
    t.start()
    return t
