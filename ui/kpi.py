"""
KPI / metrics data layer for the dashboard.

Every number here is REAL and reproducible — no hardcoded vanity stats:
  * operational_kpis()   → live aggregates from the messages table
  * model_quality()      → held-out golden-set metrics per channel (the honest
                           accuracy/precision/FPR numbers, same harness as CI)
  * inference_benchmark()→ measured per-message latency (timed, not guessed)
  * live_api_metrics()   → counters scraped from the API /metrics endpoint

Heavy computations (golden eval, benchmark) are cached with a short TTL so the
dashboard can refresh cheaply.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)
_ROOT = Path(__file__).resolve().parent.parent

GOLDEN = {
    "phishing": _ROOT / "PhishGuard/phish_mlm/eval/golden_eval.jsonl",
    "smishing": _ROOT / "SmishGuard/smish_mlm/eval/golden_smish.jsonl",
    "vishing": _ROOT / "VishGuard/vish_mlm/eval/golden_vish.jsonl",
}

# Per-channel CI gates (held-out golden sets).
GATES = {
    "phishing": {"min_accuracy": 0.90, "max_fpr": 0.10, "min_pump_fake_recall": 1.0},
    "smishing": {"min_accuracy": 0.90, "max_fpr": 0.10},
    "vishing":  {"min_accuracy": 0.90, "max_fpr": 0.10},
}


def _passes_channel_gate(channel: str, metrics: dict) -> bool:
    g = GATES.get(channel, GATES["phishing"])
    if metrics.get("accuracy", 0) < g["min_accuracy"]:
        return False
    if metrics.get("fpr", 1) > g["max_fpr"]:
        return False
    if "min_pump_fake_recall" in g:
        if metrics.get("pump_fake_recall", 0) < g["min_pump_fake_recall"]:
            return False
    return True

# ---- tiny TTL cache (avoid recomputing golden eval / benchmark every refresh)
_CACHE: dict = {}


def _cached(key: str, ttl: float, producer):
    now = time.time()
    hit = _CACHE.get(key)
    if hit and (now - hit[0]) < ttl:
        return hit[1]
    val = producer()
    _CACHE[key] = (now, val)
    return val


# --------------------------------------------------------------- operational
def operational_kpis() -> dict | None:
    """Live aggregates from the DB. Returns None if the DB is unavailable."""
    try:
        from Autobot.VectorDB.NullPoint_Vector import connect_db
        conn = connect_db()
        if conn is None:
            return None
        cur = conn.cursor()

        cur.execute("SELECT message_type, COUNT(*), COALESCE(SUM(is_threat),0) "
                    "FROM messages GROUP BY message_type ORDER BY 2 DESC")
        by_channel = [{"channel": r[0], "total": int(r[1]), "threats": int(r[2])}
                      for r in cur.fetchall()]

        cur.execute("SELECT COUNT(*), COALESCE(SUM(is_threat),0) FROM messages")
        total_row = cur.fetchone()
        total, threats = int(total_row[0]), int(total_row[1])

        cur.execute("SELECT metadata->>'action', COUNT(*) FROM messages "
                    "WHERE metadata ? 'action' GROUP BY 1")
        action_dist = {(r[0] or "unknown"): int(r[1]) for r in cur.fetchall()}

        cur.execute("SELECT metadata->>'anomaly_level', COUNT(*) FROM messages "
                    "WHERE metadata ? 'anomaly_level' GROUP BY 1")
        anomaly_dist = {(r[0] or "unknown"): int(r[1]) for r in cur.fetchall()}

        cur.execute("SELECT date_trunc('hour', timestamp) AS hr, COUNT(*) "
                    "FROM messages WHERE is_threat=1 "
                    "AND timestamp > now() - interval '24 hours' "
                    "GROUP BY 1 ORDER BY 1")
        ts = [(r[0], int(r[1])) for r in cur.fetchall()]

        conn.close()
        return {"by_channel": by_channel, "total": total, "threats": threats,
                "action_dist": action_dist, "anomaly_dist": anomaly_dist,
                "threats_24h": ts}
    except Exception as e:
        logger.warning("operational_kpis failed: %s", e)
        return None


# ------------------------------------------------------------- model quality
def _detector(channel: str):
    if channel == "phishing":
        from PhishGuard.phish_mlm.phishing_detector import detector
    elif channel == "smishing":
        from SmishGuard.smish_mlm.smishing_detector import detector
    else:
        from VishGuard.vish_mlm.vishing_detector import detector
    return detector


def _eval_channel(channel: str) -> dict:
    path = GOLDEN[channel]
    if not path.exists():
        return {"available": False, "reason": "no golden set"}
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    from PhishGuard.phish_mlm.eval.evaluate import evaluate, passes_gate
    m = evaluate(detector=_detector(channel), rows=rows)
    m["available"] = True
    m["gate_pass"] = _passes_channel_gate(channel, m)
    return m


def model_quality(ttl: float = 300.0) -> dict:
    """Held-out golden metrics per channel (cached; same harness as CI)."""
    def _run():
        out = {}
        for ch in GOLDEN:
            try:
                out[ch] = _eval_channel(ch)
            except Exception as e:
                out[ch] = {"available": False, "reason": str(e)[:120]}
        return out
    return _cached("model_quality", ttl, _run)


# ---------------------------------------------------------------- benchmark
def inference_benchmark(n: int = 60, ttl: float = 300.0) -> dict:
    """Measured per-message verdict latency per channel (warm model)."""
    def _run():
        from common.streaming.channel_pipeline import process_one
        samples = {
            "phishing": {"subject": "Verify", "body": "Your account is suspended, verify now at http://secure-login.ru", "from": "x@secure-login.ru"},
            "smishing": {"body": "USPS: package on hold, pay fee: http://bit.ly/x", "from": "+18885550101"},
            "vishing": {"transcript": "This is the IRS, press 1 to settle your tax debt now", "from": "IRS"},
        }
        out = {}
        for ch, rec in samples.items():
            process_one(ch, rec)  # warm-up (load model/manifold)
            lat = []
            for _ in range(n):
                t0 = time.perf_counter()
                process_one(ch, rec)
                lat.append((time.perf_counter() - t0) * 1000.0)
            lat.sort()
            out[ch] = {
                "n": n,
                "avg_ms": round(sum(lat) / len(lat), 2),
                "p50_ms": round(lat[len(lat) // 2], 2),
                "p95_ms": round(lat[int(len(lat) * 0.95) - 1], 2),
                "max_ms": round(lat[-1], 2),
            }
        return out
    return _cached("benchmark", ttl, _run)


# --------------------------------------------------------------- live API
def live_api_metrics(base_url: str = "http://localhost:8000") -> dict | None:
    """Scrape a few counters from the API /metrics (best-effort)."""
    try:
        import urllib.request
        with urllib.request.urlopen(f"{base_url}/metrics", timeout=2) as resp:
            text = resp.read().decode("utf-8", "replace")
    except Exception as e:
        logger.info("live_api_metrics unavailable: %s", e)
        return None

    total_requests = 0.0
    in_flight = 0.0
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        try:
            name_part, value = line.rsplit(" ", 1)
            val = float(value)
        except ValueError:
            continue
        if name_part.startswith("http_requests_total"):
            total_requests += val
        elif name_part.startswith("http_requests_in_flight"):
            in_flight = val
    return {"total_requests": int(total_requests), "in_flight": int(in_flight)}


def model_versions() -> dict:
    """Per-channel model schema/calibration info (real attributes)."""
    out = {}
    for ch in ("phishing", "smishing", "vishing"):
        try:
            d = _detector(ch)
            out[ch] = {
                "loaded": d.clf is not None,
                "calibrated": getattr(d, "platt", None) is not None,
                "features": getattr(d, "num_features", None)
                or getattr(d, "_feature_version", None),
            }
        except Exception as e:
            out[ch] = {"loaded": False, "error": str(e)[:80]}
    return out
