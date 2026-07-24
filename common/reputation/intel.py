"""
On-demand email/URL enrichment (IPQS + URLhaus) for phish/smish paths.

Unlike the phone reputation aggregator, these are called selectively during
detection — one sender email or the first URL in a message — and always fail-open.
"""
from __future__ import annotations

import logging
from typing import Optional

from common.reputation.providers import IPQSEmailProvider, IPQSURLProvider, check_urlhaus

logger = logging.getLogger(__name__)

_email = IPQSEmailProvider()
_url = IPQSURLProvider()


def check_email_intel(email: str) -> Optional[dict]:
    """IPQS email verification for a sender address. None when disabled or clean."""
    try:
        return _email.check(email)
    except Exception as exc:
        logger.debug("email intel failed: %s", exc)
        return None


def scan_url_intel(url: str) -> Optional[dict]:
    """IPQS malicious URL scan. None when disabled, clean, or out of credits."""
    try:
        return _url.check(url)
    except Exception as exc:
        logger.debug("url intel failed: %s", exc)
        return None


def scan_url_external(url: str) -> Optional[dict]:
    """Combined URLhaus + IPQS scan. Returns the strongest hit or None."""
    hits = []
    try:
        uh = check_urlhaus(url)
        if uh and uh.get("listed"):
            hits.append({"risk": 0.9, "source": "urlhaus", "detail": uh.get("threat"), "raw": uh})
    except Exception as exc:
        logger.debug("urlhaus failed: %s", exc)
    try:
        iq = scan_url_intel(url)
        if iq and iq.get("risk", 0) > 0:
            hits.append(iq)
    except Exception as exc:
        logger.debug("ipqs url failed: %s", exc)
    if not hits:
        return None
    return max(hits, key=lambda h: h.get("risk", 0))
