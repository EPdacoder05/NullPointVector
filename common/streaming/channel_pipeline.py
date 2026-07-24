"""
Channel pipeline — wires a per-channel detector to the unified risk engine and
a persistence sink, behind one DRY interface used by both the synchronous API
path and the asynchronous streaming consumer.

    record ─▶ normalize ─▶ risk.assess(detector) ─▶ verdict ─▶ (optional) store

`process_one` is the synchronous, single-message latency path (what an SMS/voice
webhook or the API calls to get an immediate verdict). `make_consumer` wraps the
same handler in an `RTIConsumer` for high-throughput async fan-in.
"""
from __future__ import annotations

import importlib
import logging
from datetime import datetime
from typing import Optional

from common.streaming.rti_consumer import DropPolicy, RTIConsumer

logger = logging.getLogger(__name__)

# Per-channel wiring. Each channel uses its OWN anomaly manifold (fit on that
# channel's benign traffic), so novelty is calibrated per channel rather than
# borrowing the email manifold.
CHANNELS = {
    "phishing": {
        "module": "PhishGuard.phish_mlm.phishing_detector",
        "use_anomaly": True,
        "text_keys": ("body", "snippet", "message", "text"),
        "sender_keys": ("from", "sender"),
    },
    "smishing": {
        "module": "SmishGuard.smish_mlm.smishing_detector",
        "use_anomaly": True,
        "text_keys": ("body", "message", "text"),
        "sender_keys": ("from", "sender"),
    },
    "vishing": {
        "module": "VishGuard.vish_mlm.vishing_detector",
        "use_anomaly": True,
        "text_keys": ("transcript", "body", "text"),
        "sender_keys": ("caller_id", "from", "sender"),
    },
}

_detector_cache: dict = {}


def get_detector(channel: str):
    """Lazily import and cache the per-channel detector singleton."""
    if channel not in CHANNELS:
        raise ValueError(f"unknown channel: {channel}")
    if channel not in _detector_cache:
        mod = importlib.import_module(CHANNELS[channel]["module"])
        _detector_cache[channel] = mod.detector
    return _detector_cache[channel]


def _first(record: dict, keys) -> str:
    for k in keys:
        if record.get(k):
            return record[k]
    return ""


def normalize(channel: str, record: dict) -> dict:
    """Produce a record carrying every key the detector + risk engine may read."""
    cfg = CHANNELS[channel]
    text = _first(record, cfg["text_keys"])
    sender = _first(record, cfg["sender_keys"])
    return {**record, "subject": record.get("subject", ""), "body": text,
            "transcript": text, "from": sender, "caller_id": sender}


def get_channel_anomaly(channel: str, *, allow_fit: bool = True):
    """
    Per-channel anomaly detector. Email uses its existing manifold (via the
    default getter inside assess → returns None here). SMS/voice fit a manifold
    over their own benign seed corpus and persist it next to the model.
    """
    if channel == "phishing":
        return None  # assess() falls back to the email manifold
    from common.ml.anomaly import get_channel_anomaly_detector
    det = get_detector(channel)

    def _normal_corpus():
        return [det.text_fn(rec) for rec, label in det.seed_fn() if int(label) == 0]

    model_path = det.model_path.parent / f"anomaly_if_{channel}.pkl"
    return get_channel_anomaly_detector(
        channel, text_fn=det.text_fn, normal_corpus_fn=_normal_corpus,
        model_path=model_path, allow_fit=allow_fit)


def process_one(channel: str, record: dict, *, allow_anomaly_fit: bool = False):
    """Synchronous single-message verdict (classifier + per-channel anomaly)."""
    from PhishGuard.phish_mlm.risk import assess  # lazy: heavy import graph
    cfg = CHANNELS[channel]
    detector = get_detector(channel)
    anomaly = None
    use_anomaly = cfg["use_anomaly"]
    if use_anomaly and channel != "phishing":
        # Hot path: load-only by default so a request never blocks on a fit.
        anomaly = get_channel_anomaly(channel, allow_fit=allow_anomaly_fit)
        if anomaly is None:
            # Manifold not built yet → classifier-only. Do NOT borrow the email
            # manifold (passing anomaly_detector=None would make assess fall back
            # to it). Run warm_anomaly() at startup to populate these.
            use_anomaly = False
    return assess(normalize(channel, record), detector=detector,
                  use_anomaly=use_anomaly, anomaly_detector=anomaly)


def warm_anomaly(channels=("smishing", "vishing")):
    """Pre-fit & persist per-channel anomaly manifolds (call at startup, off the
    hot path). Idempotent: skips channels already cached/on-disk."""
    for ch in channels:
        try:
            get_channel_anomaly(ch, allow_fit=True)
            logger.info("[%s] anomaly manifold ready", ch)
        except Exception as e:
            logger.error("[%s] anomaly warm-up failed: %s", ch, e)


def make_sink(channel: str):
    """Persistence sink: store only confirmed threats (keeps the DB signal-rich).

    Uses the durable persist path: a transient DB outage is retried and, if it
    still fails, the threat is dead-lettered (Redis/disk) and replayed later —
    so a downstream blip never loses a confirmed detection.
    """
    cfg = CHANNELS[channel]

    def _sink(record: dict, verdict):
        if not getattr(verdict, "is_threat", False):
            return
        from common.streaming.dlq import persist_threat_durable
        persist_threat_durable(
            content=_first(record, cfg["text_keys"]),
            threat_type=channel,
            sender=_first(record, cfg["sender_keys"]) or "unknown",
            metadata={"risk_score": verdict.risk_score, "action": verdict.action.value,
                      "label": 1, "channel": channel,
                      "confidence": verdict.classifier_conf,
                      "anomaly_level": verdict.anomaly_level,
                      "anomaly_novelty": verdict.anomaly_novelty,
                      "ts": datetime.utcnow().isoformat(),
                      "reasons": verdict.reasons[:3]},
        )
    return _sink


def make_consumer(channel: str, *, workers: int = 4, maxsize: int = 10_000,
                  persist: bool = True,
                  drop_policy: DropPolicy = DropPolicy.BLOCK) -> RTIConsumer:
    """Build a started-on-demand streaming consumer for one channel."""
    if channel not in CHANNELS:
        raise ValueError(f"unknown channel: {channel}")
    handler = lambda record: process_one(channel, record)
    sink = make_sink(channel) if persist else None

    def _dead_letter(record: dict, exc: Exception):
        # Handler itself failed (not just persistence): preserve the raw record
        # so it can be re-driven once the dependency recovers.
        from common.streaming.dlq import dead_letter
        dead_letter("threat", {
            "content": _first(record, CHANNELS[channel]["text_keys"]),
            "threat_type": channel,
            "sender": _first(record, CHANNELS[channel]["sender_keys"]) or "unknown",
            "metadata": {"label": 1, "channel": channel, "reason": "handler_error",
                         "error": str(exc), "ts": datetime.utcnow().isoformat()},
        })

    return RTIConsumer(handler, workers=workers, maxsize=maxsize,
                       on_verdict=sink, drop_policy=drop_policy,
                       on_dead_letter=_dead_letter, name=channel)
