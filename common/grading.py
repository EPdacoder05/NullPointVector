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

# Only independently verified labels may be folded back into training from the
# operational database.  Model predictions, inferred ``is_threat`` flags, and
# unproven user reports are evidence for review -- never ground truth.
TRUSTED_DB_LABEL_SOURCES = frozenset({
    "human_grade",
    "analyst_verified",
    "vendor_verified",
})
TRUSTED_FEEDBACK_SOURCES = frozenset({
    "console-grade",
    "call-log-grade",
    "api-analyst-feedback",
    # Anonymized harvest on account delete — keeps fleet model signal.
    "retained-verified",
})


def _binary_label(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int) and value in (0, 1):
        return value
    if isinstance(value, str) and value.strip() in ("0", "1"):
        return int(value.strip())
    return None


def trusted_feedback_label(row: dict) -> Optional[int]:
    """Return a feedback label only when an authenticated code path sourced it."""
    if not isinstance(row, dict):
        return None
    source = str(row.get("source") or "").strip().lower()
    if source not in TRUSTED_FEEDBACK_SOURCES:
        return None
    return _binary_label(row.get("label"))


def trusted_db_label(row: dict) -> Optional[int]:
    """Return a verified binary DB label, otherwise ``None``.

    The explicit provenance requirement prevents a model prediction from being
    replayed as its own training label.  It also keeps weak/vendor observations
    out of the champion loop until an independent verifier promotes them.
    """
    if not isinstance(row, dict):
        return None
    metadata = row.get("metadata") or {}
    if not isinstance(metadata, dict):
        return None
    source = str(metadata.get("label_source") or "").strip().lower()
    if source not in TRUSTED_DB_LABEL_SOURCES:
        return None
    value = row.get("label")
    if value is None:
        value = metadata.get("label")
    return _binary_label(value)

_REPO = Path(__file__).resolve().parent.parent
_BUFFER_PATHS = {
    "phishing": _REPO / "PhishGuard" / "phish_mlm" / "data" / "feedback.jsonl",
    "smishing": _REPO / "SmishGuard" / "smish_mlm" / "models" / "feedback.jsonl",
    "vishing": _REPO / "VishGuard" / "vish_mlm" / "models" / "feedback.jsonl",
}


def feedback_buffer_path(channel: str) -> Optional[Path]:
    """Durable per-channel feedback.jsonl path, or None if channel unknown."""
    return _BUFFER_PATHS.get(channel)


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
