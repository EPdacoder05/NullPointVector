"""
Reputation aggregator: fan out a number to every enabled provider (in parallel),
fuse the results, and cache the verdict so we don't re-bill vendors per call.

Cache: Redis when available (shared across API replicas), else a small in-process
TTL dict. Cache key is the normalized number; TTL is short enough to catch a
number flipping bad, long enough to absorb ret/repeat calls (default 6h).

Complexity: lookup is O(P) provider calls done concurrently → wall-clock ≈ the
slowest provider (bounded by REPUTATION_HTTP_TIMEOUT), not the sum.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from common.reputation.base import (
    ReputationProvider, ReputationScore, Verdict, fuse, normalize_number,
)
from common.reputation.providers import default_providers

logger = logging.getLogger(__name__)

_CACHE_TTL = int(os.getenv("REPUTATION_CACHE_TTL", str(6 * 3600)))
_CACHE_PREFIX = "rep:"


class _LocalTTLCache:
    """Tiny thread-safe TTL cache for the no-Redis path."""
    def __init__(self):
        self._d: dict[str, tuple[float, dict]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            item = self._d.get(key)
            if not item:
                return None
            exp, val = item
            if exp < time.time():
                self._d.pop(key, None)
                return None
            return val

    def set(self, key: str, val: dict, ttl: int) -> None:
        with self._lock:
            self._d[key] = (time.time() + ttl, val)


class ReputationAggregator:
    def __init__(self, providers: Optional[list[ReputationProvider]] = None):
        self._providers = providers if providers is not None else default_providers()
        self._local_cache = _LocalTTLCache()

    @property
    def enabled_providers(self) -> list[ReputationProvider]:
        return [p for p in self._providers if p.enabled]

    # --------------------------------------------------------------- cache layer
    def _cache_get(self, number: str) -> Optional[ReputationScore]:
        key = _CACHE_PREFIX + number
        try:
            from common.redis_client import get_redis
            r = get_redis()
            if r is not None:
                blob = r.get(key)
                if blob:
                    return _score_from_dict(json.loads(blob))
        except Exception as e:
            logger.debug("reputation cache get failed: %s", e)
        cached = self._local_cache.get(key)
        return _score_from_dict(cached) if cached else None

    def _cache_set(self, number: str, score: ReputationScore) -> None:
        key = _CACHE_PREFIX + number
        payload = score.to_dict()
        try:
            from common.redis_client import get_redis
            r = get_redis()
            if r is not None:
                r.setex(key, _CACHE_TTL, json.dumps(payload))
                return
        except Exception as e:
            logger.debug("reputation cache set failed: %s", e)
        self._local_cache.set(key, payload, _CACHE_TTL)

    # ------------------------------------------------------------------- lookup
    def score(self, raw_number: str, *, use_cache: bool = True) -> ReputationScore:
        number = normalize_number(raw_number)
        if not number:
            return ReputationScore(number="", verdict=Verdict.UNKNOWN)

        if use_cache:
            cached = self._cache_get(number)
            if cached is not None:
                return cached

        providers = self.enabled_providers
        parts: list[ReputationScore] = []
        if providers:
            # Fan out concurrently; the slowest provider bounds latency.
            with ThreadPoolExecutor(max_workers=min(8, len(providers))) as ex:
                futures = {ex.submit(p.lookup, number): p for p in providers}
                for fut in as_completed(futures):
                    res = fut.result()
                    if res is not None:
                        parts.append(res)

        fused = fuse(number, parts)
        if use_cache:
            self._cache_set(number, fused)
        return fused


def _score_from_dict(d: dict) -> ReputationScore:
    return ReputationScore(
        number=d.get("number", ""),
        risk=float(d.get("risk", 0.0)),
        verdict=Verdict(d.get("verdict", "unknown")),
        categories=list(d.get("categories", [])),
        sources=list(d.get("sources", [])),
        report_count=int(d.get("report_count", 0)),
        confidence=float(d.get("confidence", 0.0)),
    )


_aggregator: Optional[ReputationAggregator] = None
_agg_lock = threading.Lock()


def get_aggregator() -> ReputationAggregator:
    """Process-wide singleton aggregator."""
    global _aggregator
    if _aggregator is None:
        with _agg_lock:
            if _aggregator is None:
                _aggregator = ReputationAggregator()
    return _aggregator


def score_number(raw_number: str, *, use_cache: bool = True) -> ReputationScore:
    """Convenience: score a single number via the shared aggregator."""
    return get_aggregator().score(raw_number, use_cache=use_cache)
