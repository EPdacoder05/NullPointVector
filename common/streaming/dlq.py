"""
Best-effort durable dead-letter queue (DLQ) for transient downstream failures.

Layered durability (defence in depth):
  1. Redis list  ``dlq:{kind}``           — survives app restart, shared across replicas.
  2. Disk JSONL  ``data/dlq/{kind}.jsonl`` — survives even if Redis is ALSO down.

A background drainer replays entries into the real sink once the dependency
recovers. Enqueue success is observable; if both Redis and disk fail, callers
receive ``False`` and must surface/metric that failure rather than claiming the
item is durable.

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

from common.tenant_rls import TenantContextError, require_account_sub

logger = logging.getLogger(__name__)

_DLQ_DIR = Path(os.getenv("DLQ_DIR", "data/dlq"))
_disk_lock = threading.Lock()


def _disk_path(kind: str) -> Path:
    _DLQ_DIR.mkdir(parents=True, exist_ok=True)
    return _DLQ_DIR / f"{kind}.jsonl"


# ------------------------------------------------------------------ enqueue
def dead_letter(kind: str, payload: dict) -> bool:
    """Append ``payload`` to the DLQ and report whether it was accepted.

    The function never raises because it is used on failure paths. It also never
    logs the payload: message bodies may contain customer data.
    """
    if kind in {"threat", "processing"}:
        try:
            tenant = require_account_sub(payload.get("account_sub"))
        except TenantContextError:
            logger.error("refusing tenantless %s dead letter", kind)
            return False
        payload = {**payload, "account_sub": tenant}
    line = json.dumps(payload, default=str)
    try:
        from common.redis_client import get_redis
        r = get_redis()
        if r is not None:
            r.rpush(f"dlq:{kind}", line)
            return True
    except Exception as e:  # redis flaky → fall through to disk
        logger.warning("DLQ redis push failed (%s); using disk fallback", e)
    try:
        with _disk_lock, _disk_path(kind).open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return True
    except Exception as e:
        logger.critical("DLQ disk write failed for kind=%s: %s", kind, e)
        return False


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
def persist_threat_durable(*, account_sub: str, content: str, threat_type: str, sender: str,
                           metadata: dict, retries: int = 2, backoff: float = 0.2) -> bool:
    """Store a confirmed threat with bounded retry; dead-letter on exhaustion.

    Returns True if persisted, False if dead-lettered (still durable, just deferred).
    Never raises — safe to call from a background task or stream worker.
    """
    try:
        tenant = require_account_sub(account_sub)
    except TenantContextError:
        # A tenantless item cannot be safely persisted or replayed. In
        # particular, do not put it on the shared DLQ where a future worker
        # might guess an owner.
        logger.error("refusing tenantless threat persistence")
        return False

    last = None
    for attempt in range(retries + 1):
        try:
            from Autobot.VectorDB.NullPoint_Vector import store_threat
            res = store_threat(content=content, threat_type=threat_type,
                               sender=sender, metadata=metadata,
                               account_sub=tenant)
            if isinstance(res, dict) and not res.get("error"):
                return True
            last = res
        except Exception as e:
            last = {"error": str(e)}
        time.sleep(backoff * (attempt + 1))
    queued = dead_letter("threat", {"account_sub": tenant, "content": content,
                                     "threat_type": threat_type,
                                     "sender": sender, "metadata": metadata})
    if queued:
        logger.warning("threat persist failed after %d tries (%s) → deferred",
                       retries + 1, last)
    else:
        logger.critical("threat persistence and DLQ enqueue both failed")
    return False


def _threat_sink(payload: dict) -> bool:
    try:
        tenant = require_account_sub(payload.get("account_sub"))
    except TenantContextError:
        # Preserve legacy/unowned entries in the DLQ for explicit migration;
        # never replay them into an arbitrary tenant.
        logger.error("refusing tenantless threat DLQ replay")
        return False

    from Autobot.VectorDB.NullPoint_Vector import store_threat
    res = store_threat(content=payload.get("content", ""),
                       threat_type=payload.get("threat_type", "phishing"),
                       sender=payload.get("sender", "unknown"),
                       metadata=payload.get("metadata") or {},
                       account_sub=tenant)
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
