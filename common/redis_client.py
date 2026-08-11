"""
Shared Redis connection (optional).

When REDIS_URL is unset, callers fall back to in-memory implementations.
When set, rate-limit and idempotency are shared across API replicas — O(1) per
key via Redis atomic ops (INCR/SET NX), not O(n) scan.

Complexity: each check is O(1) network round-trip (~0.1–1ms on LAN).
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_redis():
    """Return a redis.Redis client or None if REDIS_URL is not configured."""
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        return None
    try:
        import redis
        client = redis.from_url(url, decode_responses=True, socket_connect_timeout=2)
        client.ping()
        logger.info("Redis connected: %s", url.split("@")[-1])  # hide creds
        return client
    except Exception as e:
        logger.warning("Redis unavailable (%s); using in-memory fallbacks", e)
        return None
