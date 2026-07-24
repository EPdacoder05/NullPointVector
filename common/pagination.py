"""
Opaque keyset (cursor) pagination helpers.

A cursor is an opaque, URL-safe base64 token wrapping the last-seen sort key
(here: the row id). Clients treat it as a black box and just pass `next_cursor`
back. Keyset pagination is O(log N) per page (indexed seek) vs OFFSET's O(N)
scan — essential for deep pages at millions of rows.
"""
import base64
import json
from typing import Any, Dict, List, Optional


def encode_cursor(value: Any) -> Optional[str]:
    if value is None:
        return None
    raw = json.dumps({"k": value}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode()


def decode_cursor(cursor: Optional[str]) -> Optional[Any]:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor.encode())
        return json.loads(raw).get("k")
    except Exception:
        return None  # malformed cursor → treat as first page (no crash)


def page_envelope(items: List[Dict], next_key: Any, limit: int) -> Dict:
    """Standard pagination response envelope."""
    return {
        "items": items,
        "count": len(items),
        "limit": limit,
        "next_cursor": encode_cursor(next_key),
        "has_more": next_key is not None,
    }
