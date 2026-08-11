"""Grade velocity → early ephemeral campaign nudge (not champion promote).

If >= N grades share a campaign fingerprint within a window, fire extra
partial_fit nudges so active campaigns adapt in hours — durable weights still
only promote via nightly golden gate.
"""
from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict
from typing import Any, Optional

logger = logging.getLogger("grade_velocity")

_WINDOW_S = 60 * 60
_THRESHOLD = 8
_HITS: dict[str, list[float]] = defaultdict(list)


def campaign_id_from_sender(sender: str) -> str:
    """Stable short id from mailbox domain (or full sender if no @)."""
    s = (sender or "").strip().lower()
    if "@" in s:
        dom = s.rsplit("@", 1)[-1].strip(">")
        return hashlib.sha256(dom.encode()).hexdigest()[:16]
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def note_grade(*, channel: str, sender: str, verdict: str,
               record: Optional[dict] = None) -> dict[str, Any]:
    """Record a grade hit; if velocity trips, apply one extra nudge batch.

    Returns {campaign_id, count, fired, nudge}.
    """
    out: dict[str, Any] = {
        "campaign_id": "", "count": 0, "fired": False, "nudge": None,
    }
    if verdict not in ("block", "safe"):
        return out
    cid = campaign_id_from_sender(sender)
    out["campaign_id"] = cid
    key = f"{channel}:{cid}"
    now = time.time()
    bucket = [t for t in _HITS[key] if now - t < _WINDOW_S]
    bucket.append(now)
    _HITS[key] = bucket
    out["count"] = len(bucket)
    if len(bucket) < _THRESHOLD:
        return out
    # Fire at most once per window crossing (when count == threshold)
    if len(bucket) != _THRESHOLD:
        return out
    out["fired"] = True
    if record:
        try:
            from common.ml.nudge import apply_nudge
            label = 1 if verdict == "block" else 0
            out["nudge"] = apply_nudge(channel, record, is_threat=bool(label))
            logger.info(
                "grade velocity early nudge channel=%s campaign=%s n=%s",
                channel, cid, len(bucket),
            )
        except Exception as e:
            logger.warning("velocity nudge failed: %s", e)
            out["nudge"] = {"ok": False, "error": str(e)}
    return out
