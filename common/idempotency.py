"""
Idempotency-key store — replay-safe write endpoints.

Client sends an `Idempotency-Key` header on POSTs. The FIRST request acquires
the key (state PROCESSING) and does the work; concurrent/retried duplicates get
the cached result (COMPLETED) or a 409 (still PROCESSING). Prevents
double-execution on client retries, proxy retries, or at-least-once delivery.

- Atomic compare-and-set via a lock → no race between check and set.
- Terminal records (COMPLETED/FAILED) are immutable.
- Lazy TTL eviction → bounded memory without a GC thread.
- O(1) time/space per key. Swap InMemory → Redis/Postgres for multi-instance.

Adapted from System-Design-Engineering-Universal-Reference/api/idempotency.py.
"""
import hashlib
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Generator, Optional

_MAX_KEY_LEN = 128
_DEFAULT_TTL = 86_400  # 24h


class IdempotencyState(str, Enum):
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class IdempotencyRecord:
    key: str
    state: IdempotencyState
    created_at: float = field(default_factory=time.monotonic)
    result: Optional[Any] = None
    key_hash: str = ""
    request_hash: str = ""

    def __post_init__(self):
        if not self.key_hash:
            self.key_hash = hashlib.sha256(self.key.encode()).hexdigest()[:16]

    @property
    def is_terminal(self) -> bool:
        return self.state in (IdempotencyState.COMPLETED, IdempotencyState.FAILED)


class DuplicateRequestError(Exception):
    """Raised when a same-key request is still PROCESSING → caller returns 409."""


class IdempotencyConflictError(Exception):
    """The caller reused a key for a different operation payload."""


class InMemoryIdempotencyStore:
    def __init__(self, ttl_seconds: int = _DEFAULT_TTL):
        self.ttl = ttl_seconds
        self._store: Dict[str, IdempotencyRecord] = {}
        self._lock = threading.Lock()

    def _expired(self, rec: IdempotencyRecord) -> bool:
        return (time.monotonic() - rec.created_at) > self.ttl

    def get(self, key: str) -> Optional[IdempotencyRecord]:
        with self._lock:
            rec = self._store.get(key)
            if rec and self._expired(rec):
                del self._store[key]
                return None
            return rec

    def cas(self, key: str, request_hash: str = "") -> IdempotencyRecord:
        """Atomically create a PROCESSING record; raise if one already exists."""
        with self._lock:
            rec = self._store.get(key)
            if rec and not self._expired(rec):
                if rec.request_hash != request_hash:
                    raise IdempotencyConflictError(rec.key_hash)
                if rec.is_terminal:
                    return rec               # replay terminal result
                raise DuplicateRequestError(rec.key_hash)
            new = IdempotencyRecord(
                key=key,
                state=IdempotencyState.PROCESSING,
                request_hash=request_hash,
            )
            self._store[key] = new
            return new

    def complete(self, key: str, result: Any) -> None:
        with self._lock:
            rec = self._store.get(key)
            if rec and rec.state == IdempotencyState.PROCESSING:
                rec.state = IdempotencyState.COMPLETED
                rec.result = result

    def fail(self, key: str) -> None:
        with self._lock:
            rec = self._store.get(key)
            if rec and rec.state == IdempotencyState.PROCESSING:
                # Allow retry by dropping the record.
                del self._store[key]


def validate_key(key: str) -> str:
    if not key or len(key) > _MAX_KEY_LEN:
        raise ValueError(f"idempotency key must be 1..{_MAX_KEY_LEN} chars")
    return key


@dataclass
class _Ctx:
    already_completed: bool
    stored_result: Any = None
    result: Any = None


@contextmanager
def idempotent(store: InMemoryIdempotencyStore, key: str,
               request_hash: str = "") -> Generator[_Ctx, None, None]:
    """
    Usage:
        with idempotent(store, key) as ctx:
            if ctx.already_completed:
                return ctx.stored_result
            ctx.result = do_work()
        return ctx.result
    """
    validate_key(key)
    rec = store.cas(key, request_hash=request_hash)
    if rec.is_terminal:
        yield _Ctx(already_completed=True, stored_result=rec.result)
        return
    ctx = _Ctx(already_completed=False)
    try:
        yield ctx
    except Exception:
        store.fail(key)
        raise
    else:
        store.complete(key, ctx.result)


class RedisIdempotencyStore:
    """
    Redis-backed idempotency — O(1) SET NX + GET per key.

    Keys: idem:{key} → JSON {state, result}. PROCESSING uses NX+TTL; COMPLETED
    is immutable until TTL expiry. Safe across replicas (CP on Redis).
    """

    def __init__(self, redis_client, ttl_seconds: int = _DEFAULT_TTL,
                 key_prefix: str = "idem:"):
        import json as _json
        self._r = redis_client
        self.ttl = ttl_seconds
        self._prefix = key_prefix
        self._json = _json

    def _rk(self, key: str) -> str:
        return f"{self._prefix}{key}"

    def get(self, key: str) -> Optional[IdempotencyRecord]:
        raw = self._r.get(self._rk(key))
        if not raw:
            return None
        data = self._json.loads(raw)
        return IdempotencyRecord(
            key=key, state=IdempotencyState(data["state"]),
            result=data.get("result"), key_hash=data.get("key_hash", ""),
            request_hash=data.get("request_hash", ""),
        )

    def cas(self, key: str, request_hash: str = "") -> IdempotencyRecord:
        rk = self._rk(key)
        existing = self.get(key)
        if existing:
            if existing.request_hash != request_hash:
                raise IdempotencyConflictError(existing.key_hash or key[:16])
            if existing.is_terminal:
                return existing
            raise DuplicateRequestError(existing.key_hash or key[:16])
        rec = IdempotencyRecord(
            key=key,
            state=IdempotencyState.PROCESSING,
            request_hash=request_hash,
        )
        payload = self._json.dumps({
            "state": rec.state.value,
            "key_hash": rec.key_hash,
            "request_hash": request_hash,
        })
        if not self._r.set(rk, payload, nx=True, ex=self.ttl):
            existing = self.get(key)
            if existing and existing.request_hash != request_hash:
                raise IdempotencyConflictError(existing.key_hash or key[:16])
            if existing and existing.is_terminal:
                return existing
            raise DuplicateRequestError(key[:16])
        return rec

    def complete(self, key: str, result: Any) -> None:
        rk = self._rk(key)
        rec = self.get(key)
        if rec and rec.state == IdempotencyState.PROCESSING:
            payload = self._json.dumps({
                "state": IdempotencyState.COMPLETED.value,
                "result": _serialize_result(result),
                "key_hash": rec.key_hash,
                "request_hash": rec.request_hash,
            })
            self._r.set(rk, payload, ex=self.ttl)

    def fail(self, key: str) -> None:
        self._r.delete(self._rk(key))


def build_idempotency_store():
    """Factory: Redis when REDIS_URL set, else in-memory."""
    from common.redis_client import get_redis
    r = get_redis()
    if r is not None:
        return RedisIdempotencyStore(r)
    return InMemoryIdempotencyStore()


def _serialize_result(result: Any) -> Any:
    """Make idempotency payloads JSON-safe (Pydantic → dict)."""
    if hasattr(result, "model_dump"):
        return result.model_dump()
    return result
