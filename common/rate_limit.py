"""
Token-bucket rate limiting.

- O(1) time and O(1) space PER KEY (one (tokens, last_refill) tuple).
- Burst up to `capacity`, sustained `refill_rate` tokens/sec.
- In-memory by default. For horizontally-scaled (millions of users, many API
  pods) deployments, swap in RedisTokenBucket so the limit is shared across
  instances — the FastAPI dependency is identical either way.

Adapted from System-Design-Engineering-Universal-Reference/api/rate_limiter.py.
"""
import os
import hashlib
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from collections import OrderedDict
from typing import Optional, Tuple

from fastapi import HTTPException, Request, status


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: float
    retry_after: float = 0.0


class BaseRateLimiter(ABC):
    @abstractmethod
    def check(self, key: str) -> Tuple[bool, RateLimitResult]:
        """Consume one unit for `key`; O(1). Return (allowed, result)."""


@dataclass
class _Bucket:
    tokens: float
    last_refill: float = field(default_factory=time.monotonic)


class TokenBucketRateLimiter(BaseRateLimiter):
    def __init__(self, capacity: float = 120, refill_rate: float = 20,
                 cost: float = 1.0, max_buckets: int = 100_000):
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.cost = float(cost)
        self.max_buckets = max(1, int(max_buckets))
        self._buckets: "OrderedDict[str, _Bucket]" = OrderedDict()
        self._lock = threading.Lock()

    def check(self, key: str) -> Tuple[bool, RateLimitResult]:
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                if len(self._buckets) >= self.max_buckets:
                    self._buckets.popitem(last=False)
                b = _Bucket(tokens=self.capacity, last_refill=now)
                self._buckets[key] = b
            else:
                self._buckets.move_to_end(key)
            # Refill proportional to elapsed time.
            b.tokens = min(self.capacity, b.tokens + (now - b.last_refill) * self.refill_rate)
            b.last_refill = now
            if b.tokens >= self.cost:
                b.tokens -= self.cost
                return True, RateLimitResult(True, b.tokens)
            retry_after = (self.cost - b.tokens) / self.refill_rate
            return False, RateLimitResult(False, b.tokens, retry_after)


# --------------------------------------------------------- key + dependency
def client_key(request: Request) -> str:
    """
    Identify the caller for rate-limiting: authenticated user > API key > IP.
    Header values are hashed in full; prefixes are neither stored nor logged.
    Proxy-supplied client-IP headers are intentionally ignored because this
    layer cannot prove which hop authored them.
    """
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return "tok:" + hashlib.sha256(auth[7:].encode("utf-8")).hexdigest()
    api_key = request.headers.get("x-api-key")
    if api_key:
        return "key:" + hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    ip = request.client.host if request.client else "unknown"
    return f"ip:{ip}"


class RedisTokenBucketRateLimiter(BaseRateLimiter):
    """
    Distributed token bucket — O(1) per key via one Lua script (atomic).

    Shared across API replicas; latency depends on the deployed Redis path and
    must be measured rather than assumed.
    """

    _LUA = """
    local key = KEYS[1]
    local cap = tonumber(ARGV[1])
    local rate = tonumber(ARGV[2])
    local cost = tonumber(ARGV[3])
    local now = tonumber(ARGV[4])
    local data = redis.call('HMGET', key, 'tokens', 'ts')
    local tokens = tonumber(data[1])
    local ts = tonumber(data[2])
    if tokens == nil then
        tokens = cap
        ts = now
    else
        tokens = math.min(cap, tokens + (now - ts) * rate)
    end
    if tokens >= cost then
        tokens = tokens - cost
        redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
        redis.call('EXPIRE', key, math.ceil(cap / rate) + 60)
        return {1, tokens}
    end
    local retry = (cost - tokens) / rate
    redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
    redis.call('EXPIRE', key, math.ceil(cap / rate) + 60)
    return {0, tokens, retry}
    """

    def __init__(self, redis_client, capacity: float = 120, refill_rate: float = 20,
                 cost: float = 1.0, key_prefix: str = "rl:"):
        self._r = redis_client
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.cost = float(cost)
        self._prefix = key_prefix
        self._script = self._r.register_script(self._LUA)

    def check(self, key: str) -> Tuple[bool, RateLimitResult]:
        rk = f"{self._prefix}{key}"
        allowed, tokens, *rest = self._script(
            keys=[rk],
            args=[self.capacity, self.refill_rate, self.cost, time.time()],
        )
        if int(allowed) == 1:
            return True, RateLimitResult(True, float(tokens))
        retry = float(rest[0]) if rest else 1.0
        return False, RateLimitResult(False, float(tokens), retry)


# Global default limiter (env-tunable). Uses Redis when REDIS_URL is set.
def _build_default_limiter() -> BaseRateLimiter:
    from common.redis_client import get_redis
    r = get_redis()
    if r is not None:
        return RedisTokenBucketRateLimiter(
            r,
            capacity=float(os.getenv("RATE_LIMIT_CAPACITY", "120")),
            refill_rate=float(os.getenv("RATE_LIMIT_REFILL", "20")),
        )
    return TokenBucketRateLimiter(
        capacity=float(os.getenv("RATE_LIMIT_CAPACITY", "120")),
        refill_rate=float(os.getenv("RATE_LIMIT_REFILL", "20")),
        max_buckets=int(os.getenv("RATE_LIMIT_MAX_BUCKETS", "100000")),
    )


_DEFAULT = _build_default_limiter()


def rate_limit(limiter: Optional[BaseRateLimiter] = None):
    """FastAPI dependency: raise 429 (with Retry-After) when the bucket is empty."""
    lim = limiter or _DEFAULT

    def _dep(request: Request) -> None:
        allowed, result = lim.check(client_key(request))
        # Surface limit headers for well-behaved clients.
        request.state.rate_remaining = result.remaining
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(int(result.retry_after) + 1)},
            )

    return _dep
