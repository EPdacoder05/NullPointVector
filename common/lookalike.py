"""Sender-domain typosquat / lookalike detection (not body digit-swap).

LOOKALIKE_DOMAIN = the From host is a near-miss of a known brand domain
(paypa1.com, arnazon.com). Distinct from HTML_OBFUSCATION (body text) and
HOMOGRAPH (confusable Unicode scripts).
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

# brand slug → legitimate registrable domains
_BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me"),
    "amazon": ("amazon.com", "amazon.co.uk", "amzn.com"),
    "apple": ("apple.com", "icloud.com", "me.com"),
    "microsoft": ("microsoft.com", "live.com", "outlook.com", "office.com"),
    "google": ("google.com", "gmail.com", "youtube.com"),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com", "bofa.com"),
    "netflix": ("netflix.com",),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "usps": ("usps.com",),
    "irs": ("irs.gov",),
    "chime": ("chime.com",),
    "capitalone": ("capitalone.com",),
    "github": ("github.com", "githubusercontent.com"),
}

_DIGIT_MAP = str.maketrans("01345", "oieas")


def _registrable(host: str) -> str:
    h = (host or "").lower().strip().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    parts = h.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h


def _norm_slug(s: str) -> str:
    s = (s or "").lower()
    s = s.translate(_DIGIT_MAP)
    return re.sub(r"[^a-z]", "", s)


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins = cur[j - 1] + 1
            delete = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def lookalike_brand_domain(sender_or_host: str) -> Optional[Tuple[str, str]]:
    """Return (brand, evidence_host) if From host typosquats a brand, else None."""
    host = sender_or_host or ""
    if "@" in host:
        host = host.split("@")[-1]
    host = host.strip(">;'\" ").lower()
    reg = _registrable(host)
    if not reg or "." not in reg:
        return None
    # Exact known-good → not a lookalike
    for brand, goods in _BRAND_DOMAINS.items():
        if any(reg == g or reg.endswith("." + g) for g in goods):
            return None
    slug = _norm_slug(reg.split(".")[0])
    if len(slug) < 4:
        return None
    for brand, goods in _BRAND_DOMAINS.items():
        if slug == brand:
            # slug matches brand name but registrable is not the real domain
            return brand, reg
        # near-miss: 1 edit (paypa1→paypal) or contained swap
        if abs(len(slug) - len(brand)) <= 1 and _edit_distance(slug, brand) == 1:
            return brand, reg
        if len(brand) >= 5 and brand in slug and len(slug) <= len(brand) + 3:
            # paypalsecure.evil style on left label only — already handled by != goods
            if _edit_distance(slug[: len(brand) + 1], brand) <= 1:
                return brand, reg
    return None
