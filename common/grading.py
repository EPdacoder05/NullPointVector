"""
Human grading → durable per-channel feedback buffers + optional ephemeral nudge.

The ONLY manual touchpoint in the product is grading quarantined / potential
threats.

  block  → label 1 + feedback buffer + ephemeral partial_fit (Δw proof)
  safe   → label 0 + feedback buffer + ephemeral partial_fit (Δw proof)
  unsure → NOT written to the buffer (noise); stays in review queue

Durable production weights change only when ChannelTrainer / nightly job
promotes a candidate that clears the golden gate.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("grading")

VERDICT_LABEL = {"block": 1, "safe": 0}

_REPO = Path(__file__).resolve().parent.parent
_BUFFER_PATHS = {
    "phishing": _REPO / "PhishGuard" / "phish_mlm" / "data" / "feedback.jsonl",
    "smishing": _REPO / "SmishGuard" / "smish_mlm" / "models" / "feedback.jsonl",
    "vishing": _REPO / "VishGuard" / "vish_mlm" / "models" / "feedback.jsonl",
}


def record_grade(channel: str, record: dict, verdict: str,
                 source: str = "console", *, nudge: bool = True) -> dict[str, Any]:
    """Append human verdict; optionally apply ephemeral partial_fit with Δw proof.

    Returns dict: {label, buffered, nudge}.
    """
    out: dict[str, Any] = {"label": None, "buffered": False, "nudge": None}
    label = VERDICT_LABEL.get(verdict)
    path = _BUFFER_PATHS.get(channel)
    if label is None or path is None:
        return out
    out["label"] = label
    try:
        from PhishGuard.phish_mlm.training.feedback_buffer import FeedbackBuffer
        FeedbackBuffer(path).append(record, label, source=source)
        out["buffered"] = True
    except Exception as e:
        logger.error("feedback append failed [%s/%s]: %s", channel, verdict, e)

    if nudge and out["buffered"]:
        try:
            from common.ml.nudge import apply_nudge
            out["nudge"] = apply_nudge(channel, record, is_threat=bool(label))
        except Exception as e:
            logger.error("nudge failed [%s]: %s", channel, e)
            out["nudge"] = {"ok": False, "error": str(e), "deltas": []}
    return out
