"""
Runtime configuration + production safety checks.

Validates secrets at startup so misconfigured deploys fail fast instead of
running with JWT_SECRET_KEY=CHANGE_ME_IN_PRODUCTION in the wild.
"""
from __future__ import annotations

import logging
import os
import warnings

logger = logging.getLogger(__name__)

_INSECURE_JWT = {"CHANGE_ME_IN_PRODUCTION", "changeme", "secret", ""}
_INSECURE_PW = {"changeme", "password", "admin", ""}


def validate_production_config(*, strict: bool = None) -> list[str]:
    """
    Return a list of warnings. If strict=True (or ENV=production), raise on any.
    """
    if strict is None:
        strict = os.getenv("ENV", "development").lower() in ("production", "prod")

    issues: list[str] = []

    jwt = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
    if jwt in _INSECURE_JWT or len(jwt) < 32:
        issues.append("JWT_SECRET_KEY is missing or too weak (need ≥32 chars)")

    if not os.getenv("API_ADMIN_PASSWORD_HASH"):
        pw = os.getenv("API_ADMIN_PASSWORD", "changeme")
        if pw in _INSECURE_PW:
            issues.append("API_ADMIN_PASSWORD is default 'changeme' — change before exposing")

    if strict and issues:
        raise RuntimeError("Production config invalid:\n  - " + "\n  - ".join(issues))

    for msg in issues:
        if strict:
            continue
        warnings.warn(msg, stacklevel=2)
        logger.warning("CONFIG: %s", msg)

    return issues


def api_workers() -> int:
    return max(1, int(os.getenv("API_WORKERS", "2")))


def use_gunicorn() -> bool:
    return os.getenv("USE_GUNICORN", "true").lower() in ("1", "true", "yes")
