"""
Email account connectors — OAuth2 for Gmail/Microsoft + env-backed Yahoo for pilot.

Users connect from the GUI. Tokens stored encrypted in DB when available;
dev fallback keeps refresh tokens in Redis / memory with consent flags.
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from typing import Any, Optional
from urllib.parse import urlencode

import requests

logger = logging.getLogger(__name__)

_STATE: dict[str, dict] = {}  # oauth CSRF state → meta
_CONNECTIONS: dict[str, dict] = {}  # provider → connection status (process-local)


def _public_base() -> str:
    return (os.getenv("PUBLIC_BASE_URL") or "http://localhost:8088").rstrip("/")


def connector_status() -> list[dict[str, Any]]:
    """What the Connectors page shows."""
    gmail_oauth = bool(os.getenv("GOOGLE_OAUTH_CLIENT_ID") and os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"))
    ms_oauth = bool(os.getenv("MICROSOFT_OAUTH_CLIENT_ID") and os.getenv("MICROSOFT_OAUTH_CLIENT_SECRET"))
    yahoo_env = bool(os.getenv("YAHOO_USER") and os.getenv("YAHOO_PASS"))
    gmail_env = bool(os.getenv("GMAIL_USER") and os.getenv("GMAIL_PASS"))
    outlook_env = bool(os.getenv("OUTLOOK_USER") and (os.getenv("OUTLOOK_PASSWORD") or os.getenv("OUTLOOK_PASS")))

    def _row(provider: str, mode: str, ready: bool, connected: bool, note: str) -> dict:
        return {
            "provider": provider,
            "mode": mode,
            "ready": ready,
            "connected": connected or provider in _CONNECTIONS,
            "note": note,
            "account": (_CONNECTIONS.get(provider) or {}).get("account") or "",
        }

    return [
        _row("yahoo", "app_password", yahoo_env, yahoo_env,
             "Pilot: uses YAHOO_USER / YAHOO_PASS from .env (IMAP)"),
        _row("gmail", "oauth2" if gmail_oauth else "app_password",
             gmail_oauth or gmail_env, "gmail" in _CONNECTIONS or gmail_env,
             "OAuth2 when GOOGLE_OAUTH_* set; else GMAIL_USER app password"),
        _row("microsoft", "oauth2" if ms_oauth else "app_password",
             ms_oauth or outlook_env, "microsoft" in _CONNECTIONS or outlook_env,
             "OAuth2 when MICROSOFT_OAUTH_* set; else OUTLOOK_* app password"),
    ]


def start_oauth(provider: str) -> dict[str, Any]:
    """Return authorize URL for Gmail or Microsoft."""
    state = secrets.token_urlsafe(24)
    redirect = f"{_public_base()}/app/connectors/callback/{provider}"
    _STATE[state] = {"provider": provider, "ts": time.time()}

    if provider == "gmail":
        cid = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
        if not cid:
            return {"error": "Set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET"}
        params = {
            "client_id": cid,
            "redirect_uri": redirect,
            "response_type": "code",
            "scope": "https://mail.google.com/ https://www.googleapis.com/auth/userinfo.email",
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
        return {
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params),
            "state": state,
        }

    if provider == "microsoft":
        cid = os.getenv("MICROSOFT_OAUTH_CLIENT_ID", "").strip()
        if not cid:
            return {"error": "Set MICROSOFT_OAUTH_CLIENT_ID and MICROSOFT_OAUTH_CLIENT_SECRET"}
        tenant = os.getenv("MICROSOFT_OAUTH_TENANT", "common")
        params = {
            "client_id": cid,
            "redirect_uri": redirect,
            "response_type": "code",
            "scope": "offline_access https://outlook.office.com/IMAP.AccessAsUser.All openid email",
            "state": state,
        }
        return {
            "authorize_url": (
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?"
                + urlencode(params)
            ),
            "state": state,
        }

    return {"error": f"unsupported provider: {provider}"}


def finish_oauth(provider: str, code: str, state: str) -> dict[str, Any]:
    meta = _STATE.pop(state, None)
    if not meta or meta.get("provider") != provider:
        return {"error": "invalid_state"}
    redirect = f"{_public_base()}/app/connectors/callback/{provider}"

    try:
        if provider == "gmail":
            token = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
                    "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
                    "redirect_uri": redirect,
                    "grant_type": "authorization_code",
                },
                timeout=15,
            ).json()
            if token.get("error"):
                return {"error": token.get("error_description") or token.get("error")}
            _CONNECTIONS["gmail"] = {
                "account": "gmail_oauth",
                "refresh_token": token.get("refresh_token"),
                "access_token": token.get("access_token"),
                "connected_at": time.time(),
            }
            return {"ok": True, "provider": "gmail"}

        if provider == "microsoft":
            tenant = os.getenv("MICROSOFT_OAUTH_TENANT", "common")
            token = requests.post(
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                data={
                    "code": code,
                    "client_id": os.getenv("MICROSOFT_OAUTH_CLIENT_ID"),
                    "client_secret": os.getenv("MICROSOFT_OAUTH_CLIENT_SECRET"),
                    "redirect_uri": redirect,
                    "grant_type": "authorization_code",
                },
                timeout=15,
            ).json()
            if token.get("error"):
                return {"error": token.get("error_description") or token.get("error")}
            _CONNECTIONS["microsoft"] = {
                "account": "microsoft_oauth",
                "refresh_token": token.get("refresh_token"),
                "access_token": token.get("access_token"),
                "connected_at": time.time(),
            }
            return {"ok": True, "provider": "microsoft"}
    except Exception as e:
        logger.warning("oauth finish failed: %s", e)
        return {"error": str(e)}
    return {"error": "unsupported"}


def mark_env_connected(provider: str) -> dict[str, Any]:
    """Pilot: mark Yahoo/Gmail/Outlook env credentials as the active connector."""
    mapping = {
        "yahoo": ("YAHOO_USER", "YAHOO_PASS"),
        "gmail": ("GMAIL_USER", "GMAIL_PASS"),
        "microsoft": ("OUTLOOK_USER", "OUTLOOK_PASSWORD"),
    }
    keys = mapping.get(provider)
    if not keys:
        return {"error": "unknown provider"}
    user = os.getenv(keys[0], "").strip()
    pw = os.getenv(keys[1], "").strip() or os.getenv("OUTLOOK_PASS", "").strip()
    if not user or not pw:
        return {"error": f"Missing {keys[0]} / password in .env"}
    _CONNECTIONS[provider] = {"account": user, "mode": "env", "connected_at": time.time()}
    return {"ok": True, "provider": provider, "account": user}
