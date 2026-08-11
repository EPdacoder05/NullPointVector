"""Extract and normalize phone numbers from voicemail / SMS transcripts."""
from __future__ import annotations

import re
from typing import Iterable

from common.reputation.base import normalize_number

# Loose match for spoken/punctuated numbers; normalize_number decides validity.
_PHONE_RE = re.compile(
    r"(?<!\d)(\+?1[\s.\-]*)?(?:\(?\d{3}\)?[\s.\-]*)\d{3}[\s.\-]*\d{4}(?!\d)"
)


def extract_e164_numbers(*blobs: str | None, exclude: Iterable[str] | None = None) -> list[str]:
    """Return unique E.164 numbers found in text, excluding known ids."""
    skip = set()
    for raw in exclude or []:
        n = normalize_number(str(raw or ""))
        if n:
            skip.add(n)
    found: list[str] = []
    seen: set[str] = set()
    for blob in blobs:
        if not blob:
            continue
        for m in _PHONE_RE.finditer(str(blob)):
            num = normalize_number(m.group(0))
            if not num or not num.startswith("+") or num in seen or num in skip:
                continue
            # US/CA length guard after normalize
            digits = re.sub(r"\D", "", num)
            if len(digits) < 10 or len(digits) > 15:
                continue
            seen.add(num)
            found.append(num)
    return found
