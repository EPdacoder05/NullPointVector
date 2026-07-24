"""
Recent call-screen events for pilot observability.

CallKit Call Directory cannot stream every inbound ring to your server.
What we CAN do for App Store pilot:
  1. iOS app / console POSTs /api/v1/vish/screen (or /app/screen) with caller_id
  2. We persist the ScreenResult here + threat DB
  3. GET /api/v1/vish/directory syncs block/label lists to Call Directory
  4. Optional: iOS reports post-call / voicemail transcripts for deep path

This ring buffer powers the Calls page so you can revise ML accuracy live.
Screens can be human-graded (blocked / unsure / safe) — grades feed the vishing
feedback buffer so the trainer folds them into the next gated retrain.
"""
from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from typing import Any, Optional

_LOCK = threading.Lock()
_EVENTS: deque[dict[str, Any]] = deque(maxlen=200)


def record_screen(event: dict[str, Any]) -> None:
    row = {
        "id": uuid.uuid4().hex[:12],
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "caller_id": event.get("caller_id") or "",
        "action": event.get("action") or "",
        "risk": event.get("risk"),
        "verdict": event.get("verdict") or "",
        "label": event.get("label") or "",
        "paths": event.get("paths") or [],
        "is_threat": bool(event.get("is_threat")),
        "reasons": (event.get("reasons") or [])[:3],
        "transcript": (event.get("transcript") or "")[:5000],
        "graded": "",
    }
    with _LOCK:
        _EVENTS.appendleft(row)


def list_screens(limit: int = 50) -> list[dict[str, Any]]:
    with _LOCK:
        return list(_EVENTS)[:limit]


def get_screen(event_id: str) -> Optional[dict[str, Any]]:
    with _LOCK:
        for row in _EVENTS:
            if row.get("id") == event_id:
                return dict(row)
    return None


def mark_graded(event_id: str, verdict: str) -> bool:
    with _LOCK:
        for row in _EVENTS:
            if row.get("id") == event_id:
                row["graded"] = verdict
                return True
    return False
