"""
Persist / load benchmark snapshots so /app/benchmarks never recomputes golden
eval on every page hit (that was OOM'ing the app → nginx 502).
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("bench_snapshot")
_PATH = Path(__file__).resolve().parents[1] / "data" / "benchmark_snapshot.json"
_MAX_AGE_SEC = 6 * 3600  # refresh at most every 6h via script / refresh endpoint


def load_snapshot(max_age: float = _MAX_AGE_SEC) -> dict[str, Any] | None:
    try:
        if not _PATH.exists():
            return None
        data = json.loads(_PATH.read_text(encoding="utf-8"))
        age = time.time() - float(data.get("generated_at") or 0)
        if age > max_age:
            data["stale"] = True
        else:
            data["stale"] = False
        return data
    except Exception as e:
        logger.warning("benchmark snapshot load failed: %s", e)
        return None


def save_snapshot(quality: dict, latency: dict, ops: dict | None = None) -> Path:
    payload = {
        "generated_at": time.time(),
        "quality": quality,
        "latency": latency,
        "ops": ops,
    }
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    _PATH.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return _PATH


def refresh_snapshot(*, latency_n: int = 0) -> dict[str, Any]:
    """Heavy path — call from CLI / cron, not from every HTTP request.

    latency_n=0 skips inference_benchmark (avoids OOM on small hosts).
    """
    import ui.kpi as kpi
    kpi._CACHE.pop("model_quality", None)
    kpi._CACHE.pop("benchmark", None)
    quality = kpi.model_quality(ttl=3600)
    latency: dict = {}
    if latency_n and latency_n > 0:
        try:
            latency = kpi.inference_benchmark(n=latency_n, ttl=3600)
        except Exception as e:
            logger.warning("latency bench skipped: %s", e)
            latency = {}
    ops = kpi.operational_kpis()
    save_snapshot(quality, latency, ops)
    return {"quality": quality, "latency": latency, "ops": ops}
