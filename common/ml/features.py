"""
Shared structural-feature primitives + lexicons for all detection channels.

These are the hard-to-fake, language-light signals that complement the TF-IDF
text features. Channel detectors (SMS/voice) compose these primitives into a
fixed-length numeric vector. Keeping them here means a tweak to, say, the URL
shortener list improves every channel at once (DRY).

All functions are O(len(text)) and allocation-light.
"""
from __future__ import annotations

import math
import re
from collections import Counter

# --------------------------------------------------------------------------- lexicons
URGENCY_WORDS = {
    "urgent", "immediately", "immediate", "expire", "expires", "expiring",
    "suspended", "suspend", "verify", "verification", "confirm", "action",
    "required", "limited", "now", "asap", "unusual", "unauthorized", "locked",
    "blocked", "deactivated", "overdue", "penalty", "final", "warning", "alert",
    "risk", "compromised", "today", "within",
}
CREDENTIAL_WORDS = {
    "password", "username", "login", "credential", "ssn", "social", "security",
    "pin", "otp", "code", "bank", "account", "card", "cvv", "billing", "verify",
    "identity", " id", "dob", "routing",
}
MONEY_WORDS = {
    "money", "payment", "pay", "transfer", "refund", "claim", "prize", "won",
    "winner", "reward", "cash", "deposit", "invoice", "fee", "owe", "debt",
    "bitcoin", "crypto", "wire", "zelle", "venmo", "paypal", "giftcard",
}
# Coercion / authority pressure — strong in vishing (IRS/警察/arrest scripts).
THREAT_AUTHORITY_WORDS = {
    "arrest", "warrant", "lawsuit", "legal", "irs", "police", "officer",
    "agent", "court", "subpoena", "deport", "fraud", "investigation",
    "suspended", "terminated", "fine", "prosecuted",
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "rb.gy", "cutt.ly",
    "is.gd", "shorte.st", "adf.ly", "bc.vc", "linktr.ee", "tiny.cc", "rebrand.ly",
}
SUSPICIOUS_TLDS = {
    "ru", "cn", "tk", "xyz", "ml", "click", "work", "pw", "top", "loan", "win",
    "zip", "gq", "ga", "cf", "men", "download", "bid", "review", "country",
    "racing", "science", "party", "date", "stream", "link",
}

_URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z']+")
_PHONE_RE = re.compile(r"\+?\d[\d\-\(\)\s]{8,}\d")


# --------------------------------------------------------------------------- primitives
def tokens(text: str) -> list[str]:
    return _WORD_RE.findall((text or "").lower())


def lexicon_count(text: str, lexicon: set[str]) -> int:
    """Number of (whitespace) tokens that fall inside `lexicon`. O(tokens)."""
    return sum(1 for t in tokens(text) if t in lexicon)


def urls(text: str) -> list[str]:
    return _URL_RE.findall(text or "")


def shortener_count(text: str) -> int:
    return sum(1 for u in urls(text) if any(s in u.lower() for s in URL_SHORTENERS))


def suspicious_tld_count(text: str) -> int:
    n = 0
    for u in urls(text):
        host = re.sub(r"^https?://", "", u.lower()).split("/")[0]
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            n += 1
    return n


def entropy(s: str) -> float:
    """Shannon entropy (bits/char). Random/DGA-ish strings score high."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def non_ascii_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for ch in text if ord(ch) > 127) / len(text)


def digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(ch.isdigit() for ch in text) / len(text)


def upper_ratio(text: str) -> float:
    letters = [c for c in (text or "") if c.isalpha()]
    if not letters:
        return 0.0
    return sum(c.isupper() for c in letters) / len(letters)


def has_phone(text: str) -> int:
    return int(bool(_PHONE_RE.search(text or "")))


# --------------------------------------------------------------------------- sender shape
def sender_digits(sender: str) -> str:
    return re.sub(r"\D", "", sender or "")


def sender_is_shortcode(sender: str) -> int:
    """5-6 digit short codes are common for legit AND spam SMS; a weak signal."""
    d = sender_digits(sender)
    return int(3 <= len(d) <= 6)


def sender_is_alpha(sender: str) -> int:
    """Alphanumeric sender IDs ('VERIZON', 'IRS') — spoofable display names."""
    s = (sender or "").strip()
    return int(bool(s) and any(c.isalpha() for c in s) and not sender_digits(s))


def sender_is_long_number(sender: str) -> int:
    return int(len(sender_digits(sender)) >= 10)


# --------------------------------------------------------------------------- OTP signals (SMS)
# Legit services DELIVER a code ("Your code is 558213"). Smishers ASK for one
# ("Reply with the 6-digit code we sent"). This pair separates them.
_OTP_DELIVERY_RE = re.compile(
    r"(?:verification|authentication|security|confirm(?:ation)?)\s+code\s+is\s+\d{4,8}"
    r"|\d{4,8}\s+is\s+your\s+(?:verification|authentication|otp|one[- ]time)\s+code"
    r"|(?:code|otp)\s*:\s*\d{4,8}"
    r"|your\s+(?:verification|authentication)\s+code\s*:\s*\d{4,8}",
    re.IGNORECASE,
)
_OTP_THEFT_RE = re.compile(
    r"(?:reply|send|text back|provide|read back|tell us|confirm).{0,40}(?:code|otp|pin|digit)",
    re.IGNORECASE,
)


def otp_delivery_signal(text: str) -> int:
    """Service pushes a code TO the user (legit pattern)."""
    return int(bool(_OTP_DELIVERY_RE.search(text or "")))


def otp_theft_signal(text: str) -> int:
    """Attacker asks user to REPLY with a code (smish pattern)."""
    return int(bool(_OTP_THEFT_RE.search(text or "")))
