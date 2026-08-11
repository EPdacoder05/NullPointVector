"""Authenticated marketing / newsletter dampener — not a forever allowlist.

Autonomy path: Mark Safe on newsletters → feedback → nightly gate learns.
This only stops *auth_pass* mail with clear newsletter shape from flooding
Quarantine at 100% (TLDR / Substack-class). Spoofed brand From without auth
still hits ML.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

from common.safe_domains import sender_auth_verdict

_NEWSLETTER_DOMAINS = frozenset({
    "tldrnewsletter.com", "mail.tldrnewsletter.com",
    "substack.com", "mail.substack.com",
    "beehiiv.com", "mail.beehiiv.com",
    "ghost.io",
    "strawberry.me", "mail.strawberry.me",
})

_UNSUB = ("unsubscribe", "opt out", "opt-out", "manage preferences", "view in browser")
_MALICE = (
    "wire transfer", "gift card", "password reset", "verify your account",
    "ssn", "social security", "routing number", "seed phrase", "private key",
    "urgent action required", "account suspended", "click here to unlock",
)


def _sender_domain(sender: str) -> str:
    m = re.search(r"@([A-Za-z0-9.\-]+)", sender or "")
    return (m.group(1) if m else "").lower().rstrip(".")


def is_auth_newsletter(email_data: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    if not isinstance(email_data, dict):
        return False, ""
    sender = email_data.get("from") or email_data.get("sender") or ""
    text = " ".join([
        email_data.get("subject") or "",
        email_data.get("body") or "",
        email_data.get("text") or "",
    ]).lower()
    headers = email_data.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}

    present, auth_pass, auth_fail = sender_auth_verdict(email_data)
    if auth_fail or not auth_pass:
        return False, ""

    # Hard malice language → never dampen
    if any(w in text for w in _MALICE):
        return False, ""

    dom = _sender_domain(sender)
    list_unsub = bool(
        headers.get("list-unsubscribe")
        or headers.get("List-Unsubscribe")
        or headers.get("list_unsubscribe")
    )
    unsub_body = any(w in text for w in _UNSUB)
    known_nl = any(dom == d or dom.endswith("." + d) for d in _NEWSLETTER_DOMAINS)

    if known_nl and (list_unsub or unsub_body or "tldr" in text or "newsletter" in text):
        return True, f"newsletter:{dom}"
    if list_unsub and unsub_body and present:
        return True, f"list_unsub:{dom}"
    if unsub_body and "newsletter" in text and present:
        return True, f"newsletter_body:{dom}"
    return False, ""


def predict_override(email_data: dict) -> Optional[Tuple[int, float]]:
    """Return (0, low conf) so auth newsletters stay out of Quarantine."""
    ok, _ = is_auth_newsletter(email_data)
    if not ok:
        return None
    return (0, 0.12)
