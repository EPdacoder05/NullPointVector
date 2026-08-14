"""
Runtime configuration + production safety checks.

Validates secrets at startup so misconfigured deploys fail fast instead of
running with JWT_SECRET_KEY=CHANGE_ME_IN_PRODUCTION in the wild.
"""
from __future__ import annotations

import logging
import os
import warnings
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_INSECURE_JWT = {"CHANGE_ME_IN_PRODUCTION", "changeme", "secret", ""}
_INSECURE_PW = {"changeme", "password", "admin", ""}


def is_production_environment() -> bool:
    """Detect an internet-facing deploy even when `ENV` was omitted.

    Managed platforms set one of the service markers below.  A non-loopback
    PUBLIC_BASE_URL is also production-like: falling back to development
    secrets on a public host must fail closed.
    """
    env = os.getenv("ENV", "development").strip().lower()
    if env in {"production", "prod", "staging", "stage"}:
        return True
    if any(os.getenv(name) for name in (
        "FLY_APP_NAME", "RAILWAY_ENVIRONMENT", "RENDER_SERVICE_ID",
        "K_SERVICE", "DYNO",
    )):
        return True
    public_base = os.getenv("PUBLIC_BASE_URL", "").strip()
    if not public_base:
        return False
    try:
        parsed = urlsplit(public_base)
    except ValueError:
        return True
    host = (parsed.hostname or "").lower()
    # A malformed configured public URL is not evidence of a safe local
    # runtime. Treat everything except an explicit HTTP(S) loopback as public.
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return True
    if host in {"localhost", "127.0.0.1", "::1"}:
        return False
    # Tailscale Funnel / MagicDNS is still a laptop pilot, not a managed deploy.
    if host.endswith(".ts.net"):
        return False
    return True


def validate_production_config(*, strict: bool = None) -> list[str]:
    """
    Return a list of warnings. If strict=True (or ENV=production), raise on any.
    """
    if strict is None:
        strict = is_production_environment()

    issues: list[str] = []

    jwt = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
    if jwt in _INSECURE_JWT or len(jwt) < 32:
        issues.append("JWT_SECRET_KEY is missing or too weak (need ≥32 chars)")

    if not os.getenv("API_ADMIN_PASSWORD_HASH"):
        pw = os.getenv("API_ADMIN_PASSWORD", "changeme")
        if pw in _INSECURE_PW:
            issues.append("API_ADMIN_PASSWORD is default 'changeme' — change before exposing")

    signup_requested = (
        os.getenv("SIGNUP_OPEN", "false").strip().lower() in {"1", "true", "yes"}
    )
    if strict and signup_requested:
        issues.append(
            "SIGNUP_OPEN must remain false until verified account-state support is implemented"
        )

    if strict and os.getenv("BILLING_ENABLED", "false").strip().lower() in {
        "1", "true", "yes",
    }:
        issues.append(
            "BILLING_ENABLED must remain false until webhook replay and lifecycle handling are complete"
        )

    if strict:
        public_base = os.getenv("PUBLIC_BASE_URL", "").strip()
        try:
            public_url = urlsplit(public_base)
        except ValueError:
            public_url = None
        if (
            not public_url
            or public_url.scheme.lower() != "https"
            or not public_url.hostname
            or public_url.username
            or public_url.password
            or public_url.path not in ("", "/")
            or public_url.query
            or public_url.fragment
        ):
            issues.append("PUBLIC_BASE_URL must be one canonical HTTPS origin")

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
