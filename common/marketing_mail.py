"""Authenticated marketing dampener — thin facade over policy_pipeline."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from common.policy_pipeline import extract_signals


def is_auth_newsletter(email_data: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    sig = extract_signals(email_data)
    if not sig.get("marketing"):
        return False, ""
    return True, f"newsletter:{sig.get('sender_domain') or ''}"


def predict_override(email_data: dict) -> Optional[Tuple[int, float]]:
    from common.policy_pipeline import predict_override as _po
    forced = _po(email_data)
    if forced and forced[0] == 0 and forced[1] <= 0.15:
        # marketing / auth_financial dampen band
        return forced
    return None
