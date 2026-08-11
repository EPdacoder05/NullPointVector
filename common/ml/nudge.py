"""
Ephemeral model nudge with measurable weight deltas (partial_fit proof).

Nightly / gated full retrain remains the durable path (ChannelTrainer + golden gate).
This module only:
  1. Snapshots SGD coefficients
  2. Calls channel learn_from_feedback / partial_fit
  3. Reports which word features moved (Δw)

Sibling channels share entity crumbs via ``common.ml.cross_channel``.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("nudge")


def _get_detector(channel: str):
    if channel == "phishing":
        from PhishGuard.phish_mlm.phishing_detector import detector
        return detector
    if channel == "smishing":
        from SmishGuard.smish_mlm.smishing_detector import detector
        return detector
    if channel == "vishing":
        from VishGuard.vish_mlm.vishing_detector import detector
        return detector
    raise ValueError(f"unknown channel: {channel}")


def snapshot_coef(detector) -> Optional[Any]:
    try:
        import numpy as np
        clf = getattr(detector, "clf", None)
        if clf is None or not hasattr(clf, "coef_"):
            return None
        return np.array(clf.coef_, copy=True)
    except Exception:
        return None


def word_weight_deltas(detector, before, after, k: int = 10) -> list[dict]:
    """Top-|Δ| word-vocab coefficients after one partial_fit step."""
    if before is None or after is None:
        return []
    try:
        import numpy as np
        word_tfidf = getattr(detector, "word_tfidf", None)
        if word_tfidf is None or not getattr(word_tfidf, "vocabulary_", None):
            return []
        b = np.asarray(before).ravel()
        a = np.asarray(after).ravel()
        n = min(len(b), len(a), len(word_tfidf.vocabulary_))
        delta = a[:n] - b[:n]
        order = np.argsort(np.abs(delta))[::-1][:k]
        inv = {i: t for t, i in word_tfidf.vocabulary_.items()}
        out = []
        for i in order:
            d = float(delta[int(i)])
            if abs(d) < 1e-12:
                continue
            out.append({
                "feature": inv.get(int(i), f"f{i}"),
                "before": round(float(b[int(i)]), 5),
                "after": round(float(a[int(i)]), 5),
                "delta": round(d, 5),
            })
        return out
    except Exception as e:
        logger.debug("weight delta failed: %s", e)
        return []


def apply_nudge(channel: str, record: dict, is_threat: bool) -> dict:
    """Buffer is caller's job; this only does ephemeral partial_fit + Δw proof."""
    try:
        det = _get_detector(channel)
    except Exception as e:
        logger.error("nudge detector unavailable [%s]: %s", channel, e)
        return {"ok": False, "error": "detector_unavailable", "deltas": []}

    before = snapshot_coef(det)
    try:
        # Positional 2nd arg: PhishDetector.is_phishing / ChannelDetector.is_threat.
        det.learn_from_feedback(record, is_threat)
    except Exception as e:
        logger.error("nudge failed [%s]: %s", channel, e)
        return {"ok": False, "error": "nudge_failed", "deltas": []}

    after = snapshot_coef(det)
    deltas = word_weight_deltas(det, before, after)
    try:
        from common.ml.cross_channel import share_grade_crumb
        share_grade_crumb(channel, record, is_threat=is_threat, deltas=deltas[:5])
    except Exception as e:
        logger.debug("cross-channel crumb skipped: %s", e)

    return {
        "ok": True,
        "channel": channel,
        "ephemeral": True,
        "persisted_to_disk": False,
        "deltas": deltas,
        "plain": _deltas_plain(deltas, is_threat),
    }


def _deltas_plain(deltas: list[dict], is_threat: bool) -> str:
    if not deltas:
        return (
            "We nudged the live model in memory, but no word-weight changed enough "
            "to show (often the important tokens were outside the fixed vocabulary — "
            "the nightly full retrain can grow that)."
        )
    direction = "toward threat" if is_threat else "toward safe"
    parts = [f"“{d['feature']}” {d['delta']:+.4f}" for d in deltas[:5]]
    return (
        f"One training step moved weights {direction}. Biggest movers: "
        + "; ".join(parts)
        + ". These changes live only in this running process until a gated nightly retrain."
    )
