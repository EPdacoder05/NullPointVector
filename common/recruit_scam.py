"""Recruit / job-offer scam — thin facade over policy_pipeline (no second lexicon)."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from common.policy_pipeline import extract_signals


def free_mail_recruit_scam(email_data: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    sig = extract_signals(email_data)
    if not sig.get("recruit_scam"):
        return False, ""
    # Prefer free-mail flavor when applicable
    sender = ""
    if isinstance(email_data, dict):
        sender = str(email_data.get("from") or email_data.get("sender") or "")
    if "@gmail." in sender.lower() or "@yahoo." in sender.lower():
        return True, "free_mail_recruit"
    return True, "recruit_scam"


def merge_tag_job_scam(email_data: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    sig = extract_signals(email_data)
    if sig.get("merge_tags"):
        return True, f"merge_tag_job:{sig['merge_tags'][0]}"
    if sig.get("domain_mismatch"):
        return True, "recruit_domain_mismatch"
    if sig.get("recruit_scam"):
        return True, "recruit_scam"
    return False, ""


def predict_override(email_data: dict) -> Optional[Tuple[int, float]]:
    from common.policy_pipeline import predict_override as _po
    forced = _po(email_data)
    if forced and forced[0] == 1:
        return forced
    return None
