"""Parse email Date headers to UTC — never use poll/ingest clock as message time."""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional


def parse_email_date(value: Any) -> datetime:
    """Best-effort RFC 2822 / ISO → aware UTC. Fallback = now(UTC)."""
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    raw = str(value or "").strip()
    if not raw:
        return datetime.now(timezone.utc)
    try:
        dt = parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass
    try:
        s = raw.replace("Z", "+00:00") if raw.endswith("Z") else raw
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def normalize_message_id(raw: Optional[str]) -> str:
    """Canonical Message-ID for dedup (<id@host>)."""
    s = (raw or "").strip()
    if not s:
        return ""
    if s.startswith("<") and s.endswith(">"):
        return s.lower()
    return f"<{s.strip('<>').lower()}>"
