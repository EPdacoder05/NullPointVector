"""Unified Signal Deck pills — short labels, deduped mood + evidence.

UI chips must stay terse; full prose lives in title/evidence + Why panel.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# Mood/category codes that duplicate an evidence reason code (or alias).
_SKIP_IF_PRESENT = {
    "HAPPY_LURE": {"HAPPY_LURE"},
    "IMPERSONATION": {"IMPERSONATION"},
    "BLACKMAIL": {"BLACKMAIL"},
    "ADVANCE_FEE": {"ADVANCE_FEE"},
    "FEAR_URGENCY": {"URGENCY_FEAR", "FEAR_URGENCY"},
    "SOCIAL_ENG": {"SOCIAL_ENGINEERING", "SOCIAL_ENG"},
    "RELATIONSHIP_NSFW": {"RELATIONSHIP_LURE", "RELATIONSHIP_NSFW"},
}

_HTML_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_ENTITY_RE = re.compile(r"&#?\w+;")


def strip_preview(text: str, limit: int = 220) -> str:
    """Plain-text body snippet for cards — no raw HTML/DOCTYPE bleed."""
    if not text:
        return ""
    s = _HTML_RE.sub(" ", text)
    s = _ENTITY_RE.sub(" ", s)
    s = _WS_RE.sub(" ", s).strip()
    if len(s) > limit:
        return s[: limit - 1] + "…"
    return s


def build_pills(
    *,
    channel: str,
    subject: str = "",
    body: str = "",
    sender: str = "",
    confidence: float = 0.0,
    headers: Optional[dict] = None,
    max_cats: int = 4,
    max_reasons: int = 6,
) -> Dict[str, Any]:
    """Return {tags, reason_codes, preview} ready for Jinja cards."""
    from common.explain import reason_codes_for
    from common.message_tags import categorize_message

    text = f"{subject or ''}\n{body or ''}".strip()
    reasons = reason_codes_for(
        channel or "phishing",
        text,
        sender or "",
        confidence=float(confidence or 0),
        headers=headers,
    )[:max_reasons]
    seen = {r["code"] for r in reasons}
    cats: List[Dict[str, str]] = []
    for t in categorize_message(subject=subject or "", body=body or "", sender=sender or ""):
        code = t["code"]
        rivals = _SKIP_IF_PRESENT.get(code, {code})
        if seen & rivals:
            continue
        if code in seen:
            continue
        cats.append(t)
        seen.add(code)
        if len(cats) >= max_cats:
            break
    return {
        "tags": cats,
        "reason_codes": reasons,
        "preview": strip_preview(body or ""),
    }
