"""Shared mail string helpers — one sender-domain parser for the whole tree."""
from __future__ import annotations

import re
from typing import Optional

_EMAIL_AT = re.compile(r"@([A-Za-z0-9.\-]{1,253})")


def sender_domain(sender: Optional[str]) -> str:
    """Registrable-ish host from a From: string (last labels kept as-is)."""
    m = _EMAIL_AT.search(sender or "")
    return (m.group(1) if m else "").lower().rstrip(".")


def registrable_host(host: Optional[str]) -> str:
    """Best-effort registered domain (last two labels). No tldextract."""
    h = (host or "").lower().strip().strip(".").split(":")[0].split("/")[0]
    if h.startswith("www."):
        h = h[4:]
    parts = [p for p in h.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h
