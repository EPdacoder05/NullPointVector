"""Recruit / job-offer scam patterns — raise risk before ML miss.

Covers:
  - Free-mail BCC blasts (Vandana/Vanessa class)
  - Merge-tag fraud ([[CANDIDATEEMAIL]], empty address-on-file)
  - Callback-pressure recruiters on lookalike staffing domains
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

_FREE_MAIL = re.compile(
    r"@(gmail|yahoo|hotmail|outlook|icloud|aol)\.com\b", re.I
)
_RECRUIT = (
    "you applied", "applied to this role", "twic", "temp to hire", "pay rate",
    "job description", "hello all", "active clearance", "soc analyst",
    "interview slot", "cloud performance", "job id", "duration:", "call me at",
)
_MERGE_TAGS = (
    "[[candidateemail]]", "{{candidate", "{candidate_email}", "%candidate",
    "*|email|*", "[[email]]", "address on file is .", "address on file is  .",
    "your address on file is .",
)
_CALLBACK = re.compile(
    r"(please call me at|call me at|reach me at)\s*\+?\d[\d\s\-().]{8,}",
    re.I,
)


def free_mail_recruit_scam(email_data: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    if not isinstance(email_data, dict):
        return False, ""
    sender = (email_data.get("from") or email_data.get("sender") or "")
    text = " ".join([
        email_data.get("subject") or "",
        email_data.get("body") or "",
        email_data.get("text") or "",
    ]).lower()
    if not _FREE_MAIL.search(sender):
        return False, ""
    hits = [w for w in _RECRUIT if w in text]
    if len(hits) < 2 and not ("hello all" in text and "applied" in text):
        return False, ""
    return True, f"free_mail_recruit:{','.join(hits[:4])}"


def merge_tag_job_scam(email_data: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
    """Unfilled mail-merge + job pitch = high-confidence fraud (not newsletter)."""
    if not isinstance(email_data, dict):
        return False, ""
    text = " ".join([
        email_data.get("subject") or "",
        email_data.get("body") or "",
        email_data.get("text") or "",
    ]).lower()
    sender = (email_data.get("from") or email_data.get("sender") or "").lower()

    merge_hits = [t for t in _MERGE_TAGS if t in text]
    jobbish = any(w in text for w in (
        "position:", "job id", "duration:", "recruiter", "resume", "opportunity",
        "talent software", "staffing",
    ))
    if merge_hits and jobbish:
        return True, f"merge_tag_job:{merge_hits[0]}"

    # Website domain in signature ≠ From mailbox domain (talentemail vs talentstaffing*)
    if jobbish and _CALLBACK.search(text):
        sites = re.findall(r"(?:www\.)?([a-z0-9\-]+\.(?:com|net|org))", text)
        from_dom = ""
        m = re.search(r"@([a-z0-9.\-]+)", sender)
        if m:
            from_dom = m.group(1)
        for site in sites:
            if from_dom and site not in from_dom and from_dom not in site:
                # staffing brand in body, different mail domain
                if "talent" in site or "staff" in site or "recruit" in site:
                    if "talent" in from_dom or "mail" in from_dom or "email" in from_dom:
                        return True, f"recruit_domain_mismatch:{from_dom}->{site}"
    return False, ""


def predict_override(email_data: dict) -> Optional[Tuple[int, float]]:
    ok, reason = merge_tag_job_scam(email_data)
    if ok:
        return (1, 0.94)
    ok, reason = free_mail_recruit_scam(email_data)
    if ok:
        return (1, 0.91)
    return None
