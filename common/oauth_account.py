"""Account sign-in OAuth (Google / Microsoft) for login + checkout.

Same-window redirect — callback must set the session cookie on this origin.
Mail Connect OAuth stays in common/oauth_email.py.
X / Meta buttons are visible; keys optional (setup redirect when unset).
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import requests

logger = logging.getLogger(__name__)

_STATE: dict[str, dict] = {}
_STATE_TTL_S = 15 * 60
_PRODUCTION_ACCOUNT_OAUTH_READY = False


def _prune_oauth_state(now: float | None = None) -> None:
    """Bound abandoned account-login state and reject it after 15 minutes."""
    ts_now = time.time() if now is None else now
    expired = [
        key for key, value in list(_STATE.items())
        if ts_now - float(value.get("ts") or 0) > _STATE_TTL_S
    ]
    for key in expired:
        _STATE.pop(key, None)


def _public_base() -> str:
    return (os.getenv("PUBLIC_BASE_URL") or "http://localhost:8088").rstrip("/")


def provider_ready(provider: str) -> bool:
    from common.config import is_production_environment
    if is_production_environment() and not _PRODUCTION_ACCOUNT_OAUTH_READY:
        return False
    p = (provider or "").lower()
    if p == "google":
        return bool(os.getenv("GOOGLE_OAUTH_CLIENT_ID") and os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"))
    if p == "microsoft":
        return bool(os.getenv("MICROSOFT_OAUTH_CLIENT_ID") and os.getenv("MICROSOFT_OAUTH_CLIENT_SECRET"))
    if p == "x":
        return bool(os.getenv("X_OAUTH_CLIENT_ID") and os.getenv("X_OAUTH_CLIENT_SECRET"))
    if p == "meta":
        return bool(os.getenv("META_OAUTH_CLIENT_ID") and os.getenv("META_OAUTH_CLIENT_SECRET"))
    return False


def start_account_oauth(provider: str, next_path: str = "/app/dashboard") -> dict[str, Any]:
    _prune_oauth_state()
    provider = (provider or "").lower().strip()
    next_path = (
        next_path
        if next_path == "/app" or (next_path or "").startswith("/app/")
        else "/app/dashboard"
    )
    if not provider_ready(provider):
        return {
            "error": "oauth_not_configured",
            "hint": f"Add {provider.upper()}_OAUTH_CLIENT_ID/SECRET to .env (Google uses GOOGLE_OAUTH_*).",
            "provider": provider,
        }

    state = secrets.token_urlsafe(24)
    redirect = f"{_public_base()}/app/auth/callback/{provider}"
    _STATE[state] = {"provider": provider, "next": next_path, "ts": time.time()}

    if provider == "google":
        params = {
            "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip(),
            "redirect_uri": redirect,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "online",
            "prompt": "select_account",
            "state": state,
        }
        return {
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params),
            "state": state,
        }

    if provider == "microsoft":
        tenant = os.getenv("MICROSOFT_OAUTH_TENANT", "common")
        params = {
            "client_id": os.getenv("MICROSOFT_OAUTH_CLIENT_ID", "").strip(),
            "redirect_uri": redirect,
            "response_type": "code",
            "scope": "openid email profile offline_access",
            "state": state,
        }
        return {
            "authorize_url": (
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?"
                + urlencode(params)
            ),
            "state": state,
        }

    if provider == "x":
        params = {
            "response_type": "code",
            "client_id": os.getenv("X_OAUTH_CLIENT_ID", "").strip(),
            "redirect_uri": redirect,
            "scope": "users.read tweet.read offline.access",
            "state": state,
            "code_challenge": "challenge",
            "code_challenge_method": "plain",
        }
        return {
            "authorize_url": "https://twitter.com/i/oauth2/authorize?" + urlencode(params),
            "state": state,
            "error": "x_pkce_required",
            "hint": "X OAuth needs PKCE — wire fully before enabling in prod.",
        }

    if provider == "meta":
        params = {
            "client_id": os.getenv("META_OAUTH_CLIENT_ID", "").strip(),
            "redirect_uri": redirect,
            "response_type": "code",
            "scope": "email,public_profile",
            "state": state,
        }
        return {
            "authorize_url": "https://www.facebook.com/v19.0/dialog/oauth?" + urlencode(params),
            "state": state,
        }

    return {"error": f"unsupported_provider:{provider}"}


def finish_account_oauth(provider: str, code: str, state: str) -> dict[str, Any]:
    _prune_oauth_state()
    meta = _STATE.pop(state, None)
    if not meta or meta.get("provider") != provider:
        return {"error": "invalid_state"}
    if time.time() - float(meta.get("ts") or 0) > _STATE_TTL_S:
        return {"error": "invalid_state"}
    next_path = meta.get("next") or "/app/dashboard"
    redirect = f"{_public_base()}/app/auth/callback/{provider}"

    try:
        email = ""
        if provider == "google":
            tok = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
                    "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
                    "redirect_uri": redirect,
                    "grant_type": "authorization_code",
                },
                timeout=12,
            )
            tok.raise_for_status()
            access = tok.json().get("access_token")
            info = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access}"},
                timeout=12,
            )
            info.raise_for_status()
            email = (info.json().get("email") or "").strip().lower()

        elif provider == "microsoft":
            tenant = os.getenv("MICROSOFT_OAUTH_TENANT", "common")
            tok = requests.post(
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                data={
                    "code": code,
                    "client_id": os.getenv("MICROSOFT_OAUTH_CLIENT_ID"),
                    "client_secret": os.getenv("MICROSOFT_OAUTH_CLIENT_SECRET"),
                    "redirect_uri": redirect,
                    "grant_type": "authorization_code",
                },
                timeout=12,
            )
            tok.raise_for_status()
            access = tok.json().get("access_token")
            info = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access}"},
                timeout=12,
            )
            info.raise_for_status()
            j = info.json()
            email = (j.get("mail") or j.get("userPrincipalName") or "").strip().lower()

        elif provider in ("x", "meta"):
            return {"error": "provider_pending", "next": next_path,
                    "hint": f"{provider} account OAuth UI is live; token exchange still pending keys."}

        if not email or "@" not in email:
            return {"error": "no_email", "next": next_path}

        from common.auth import create_access_token
        from datetime import timedelta
        token = create_access_token(
            {"sub": email, "role": "customer", "oauth": provider},
            expires=timedelta(hours=12),
        )
        return {"ok": True, "token": token, "email": email, "next": next_path}
    except Exception as e:
        logger.warning("account oauth finish failed: %s", e)
        return {"error": "oauth_exchange_failed", "next": next_path}
