"""
Human grading → durable per-channel feedback buffers.

The ONLY manual touchpoint in the product is grading quarantined / potential
threats. A grade never mutates a live model directly (poisoning vector);
it is appended to that channel's append-only feedback buffer, which the
ChannelTrainer folds into the next full retrain behind the golden gate.

Verdict mapping:
    block  → label 1 (confirmed threat)
    safe   → label 0 (confirmed clean)
    unsure → NOT written to the buffer (an unsure human label is noise);
             the item just stays/moves to the quarantine review queue.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("grading")

VERDICT_LABEL = {"block": 1, "safe": 0}

_REPO = Path(__file__).resolve().parent.parent
_BUFFER_PATHS = {
    "phishing": _REPO / "PhishGuard" / "phish_mlm" / "data" / "feedback.jsonl",
    "smishing": _REPO / "SmishGuard" / "smish_mlm" / "models" / "feedback.jsonl",
    "vishing": _REPO / "VishGuard" / "vish_mlm" / "models" / "feedback.jsonl",
}


def record_grade(channel: str, record: dict, verdict: str,
                 source: str = "console") -> Optional[int]:
    """Append one human verdict to the channel's feedback buffer.

    Returns the numeric label written, or None when nothing was written
    (unsure verdict, unknown channel, or buffer failure — never raises).
    """
    label = VERDICT_LABEL.get(verdict)
    path = _BUFFER_PATHS.get(channel)
    if label is None or path is None:
        return None
    try:
        from PhishGuard.phish_mlm.training.feedback_buffer import FeedbackBuffer
        FeedbackBuffer(path).append(record, label, source=source)
        return label
    except Exception as e:
        logger.error("feedback append failed [%s/%s]: %s", channel, verdict, e)
        return None
