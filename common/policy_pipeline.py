"""Single-pass policy signals → predict override (Phish hot path).

Order (one parse, one tree — not three re-scans):
  hard malice  → (1, >=0.90)
  known-good   → (0, 0.02)   # only if no hard malice + auth_pass
  marketing    → (0, 0.12)   # auth newsletter / list-unsub, no malice
  else         → None        # fall through to ML

Autonomy still: Grade → feedback → nightly gate. This is the FP/FN brake layer.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple

from common.safe_domains import is_known_good_sender, sender_auth_verdict

_HARD_MALICE = (
    "wire transfer", "gift card", "password reset", "verify your password",
    "ssn", "social security", "routing number", "seed phrase", "private key",
    "account suspended", "click here to unlock", "urgent action required",
    "pay now or be locked", "locked out", "verify payment immediately",
)
# Brand name in body + payment/urgency ask, but From/URLs are NOT that brand → spoof lure
_PAYMENT_BRAND_LURES = (
    ("paypal", ("paypal.com", "paypal.me")),
    ("venmo", ("venmo.com",)),
    ("zelle", ("zellepay.com", "zelle.com")),
    ("cash app", ("cash.app", "square.com")),
    ("cashapp", ("cash.app", "square.com")),
    ("apple pay", ("apple.com", "apple-pay.com")),
    ("google pay", ("google.com", "pay.google.com")),
)
_PAYMENT_ASK = (
    "pay now", "send payment", "make a payment", "payment required",
    "send money", "wire me", "gift card", "pay via", "pay with",
    "complete payment", "overdue payment", "invoice due",
)
_MERGE_TAGS = (
    "[[candidateemail]]", "{{candidate", "{candidate_email}",
    "address on file is .", "your address on file is .",
)
_RECRUIT = (
    "you applied", "applied to this role", "twic", "temp to hire", "pay rate",
    "job description", "hello all", "job id", "duration:", "call me at",
    "cloud performance", "recruiter", "send your resume",
)
_FREE_MAIL = re.compile(r"@(gmail|yahoo|hotmail|outlook|icloud|aol)\.com\b", re.I)
_CALLBACK = re.compile(
    r"(please call me at|call me at|reach me at)\s*\+?\d[\d\s\-().]{8,}",
    re.I,
)
_UNSUB = ("unsubscribe", "opt out", "opt-out", "manage preferences", "view in browser")
_NEWSLETTER_DOMAINS = frozenset({
    "tldrnewsletter.com", "substack.com", "beehiiv.com", "ghost.io", "strawberry.me",
})
_FINANCIAL_NOTICE = (
    "credit score", "your credit", "account alert", "sign in to your account",
    "newest report", "account statement", "balance alert", "fraud protection",
    "help prevent fraud", "card ending", "transaction alert",
)


def _auth_financial_notice(auth_pass: bool, hard_malice: bool, recruit: bool, text: str) -> bool:
    """AUTH_PASS + bank-style notice language — dampen without a fat bank list.

    Hard malice / recruit still wins. Wire/gift-card asks are hard_malice.
    """
    if not auth_pass or hard_malice or recruit:
        return False
    return any(w in text for w in _FINANCIAL_NOTICE)


def _text_blob(email_data: dict) -> str:
    return " ".join([
        str(email_data.get("subject") or ""),
        str(email_data.get("body") or ""),
        str(email_data.get("text") or ""),
    ]).lower()


def _sender(email_data: dict) -> str:
    return str(email_data.get("from") or email_data.get("sender") or "")


def _sender_domain(sender: str) -> str:
    m = re.search(r"@([A-Za-z0-9.\-]+)", sender or "")
    return (m.group(1) if m else "").lower().rstrip(".")


def _urls_and_domains(text: str, sender: str) -> set[str]:
    found = set()
    dom = _sender_domain(sender)
    if dom:
        found.add(dom)
    for m in re.finditer(r"https?://([^/\s\"'<>]+)", text or "", re.I):
        host = m.group(1).lower().split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        if host:
            found.add(host)
    return found


def _payment_brand_spoof(text: str, sender: str) -> bool:
    """PayPal/Venmo/etc. payment ask without that brand in From or links → malice.

    Real notices that actually originate from paypal.com (etc.) stay clear.
    """
    hosts = _urls_and_domains(text, sender)
    payment_ask = any(ask in text for ask in _PAYMENT_ASK) or "locked out" in text
    for brand, ok_domains in _PAYMENT_BRAND_LURES:
        if brand not in text:
            continue
        brand_pay = (
            payment_ask
            or f"pay with {brand}" in text
            or f"pay via {brand}" in text
            or f"{brand} payment" in text
            or f"send {brand}" in text
        )
        if not brand_pay:
            continue
        brand_ok = any(
            h == d or h.endswith("." + d)
            for h in hosts
            for d in ok_domains
        )
        if not brand_ok:
            return True
    return False


def extract_signals(email_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """One pass over headers/body — reusable by predict + tags."""
    if not isinstance(email_data, dict):
        email_data = {}
    sender = _sender(email_data)
    text = _text_blob(email_data)
    headers = email_data.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}

    present, auth_pass, auth_fail = sender_auth_verdict(email_data)
    hard_malice = any(w in text for w in _HARD_MALICE) or _payment_brand_spoof(text, sender)
    merge_hits = [t for t in _MERGE_TAGS if t in text]
    recruit_hits = [w for w in _RECRUIT if w in text]
    free_mail = bool(_FREE_MAIL.search(sender))
    callback = bool(_CALLBACK.search(text))
    jobbish = len(recruit_hits) >= 2 or (
        "hello all" in text and "applied" in text
    ) or bool(merge_hits and any(
        w in text for w in ("position:", "job id", "duration:", "resume", "opportunity")
    ))

    domain_mismatch = False
    if jobbish and callback:
        sites = re.findall(r"(?:www\.)?([a-z0-9\-]+\.(?:com|net|org))", text)
        from_dom = _sender_domain(sender)
        for site in sites:
            if from_dom and site not in from_dom and from_dom not in site:
                if any(k in site for k in ("talent", "staff", "recruit")):
                    if any(k in from_dom for k in ("talent", "mail", "email")):
                        domain_mismatch = True
                        break

    recruit_scam = bool(
        (merge_hits and jobbish)
        or (free_mail and (len(recruit_hits) >= 2 or ("hello all" in text and "applied" in text)))
        or domain_mismatch
    )

    list_unsub = bool(
        headers.get("list-unsubscribe")
        or headers.get("List-Unsubscribe")
        or headers.get("list_unsubscribe")
    )
    unsub_body = any(w in text for w in _UNSUB)
    dom = _sender_domain(sender)
    known_nl = any(dom == d or dom.endswith("." + d) for d in _NEWSLETTER_DOMAINS)
    marketing = bool(
        auth_pass and not hard_malice and not recruit_scam and (
            (known_nl and (list_unsub or unsub_body or "newsletter" in text or "tldr" in text))
            or (list_unsub and unsub_body)
            or (unsub_body and "newsletter" in text)
        )
    )

    known_ok, known_reason = is_known_good_sender(sender, email_data)
    # Known-good never wins over hard malice / recruit scam
    known_good = bool(known_ok and not hard_malice and not recruit_scam)
    auth_financial = _auth_financial_notice(auth_pass, hard_malice, recruit_scam, text)

    return {
        "auth_present": present,
        "auth_pass": auth_pass,
        "auth_fail": auth_fail,
        "hard_malice": hard_malice,
        "recruit_scam": recruit_scam,
        "merge_tags": merge_hits[:3],
        "domain_mismatch": domain_mismatch,
        "callback_pressure": callback,
        "known_good": known_good,
        "known_good_reason": known_reason if known_good else "",
        "marketing": marketing,
        "auth_financial": auth_financial,
        "list_unsubscribe": list_unsub,
        "sender_domain": dom,
    }


def decide_override(email_data: Optional[Dict[str, Any]]) -> Optional[Tuple[int, float]]:
    """Return (pred, conf) or None to fall through to ML."""
    sig = extract_signals(email_data)
    if sig["recruit_scam"] or (sig["hard_malice"] and not sig["auth_pass"]):
        return (1, 0.94 if sig["recruit_scam"] else 0.91)
    if sig["hard_malice"] and sig.get("callback_pressure"):
        return (1, 0.92)
    # Payment-brand spoof / hard lure even with auth stamps on a random domain
    if sig["hard_malice"] and not sig["known_good"]:
        return (1, 0.91)
    # Fleet user-report keys — soft influence only (capped); never above ML gate
    try:
        from common.user_reports import is_fleet_blocked_sender
        fleet_hit, fleet_conf = is_fleet_blocked_sender(sig.get("sender_domain") or "")
        if fleet_hit and not sig["known_good"]:
            return (1, min(0.75, float(fleet_conf or 0.75)))
    except Exception:
        pass
    if sig["known_good"]:
        return (0, 0.02)
    # AUTH_PASS financial notices (Capital One class) — auto-detect, not fat list
    if sig.get("auth_financial"):
        return (0, 0.15)
    if sig["marketing"]:
        return (0, 0.12)
    return None


def predict_override(email_data: dict) -> Optional[Tuple[int, float]]:
    """Alias used by PhishGuard.predict."""
    try:
        return decide_override(email_data)
    except Exception:
        return None
