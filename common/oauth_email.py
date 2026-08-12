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
_STATE_TTL_S = 900  # 15 minutes — abandoned OAuth starts must not leak forever


def _prune_oauth_state(now: Optional[float] = None) -> None:
    """Drop expired CSRF states. Called on start/finish; O(n) but n stays tiny."""
    ts_now = time.time() if now is None else now
    dead = [k for k, v in _STATE.items() if ts_now - float(v.get("ts") or 0) > _STATE_TTL_S]
    for k in dead:
        _STATE.pop(k, None)


def _public_base() -> str:
    return (os.getenv("PUBLIC_BASE_URL") or "http://localhost:8088").rstrip("/")


def connector_status() -> list[dict[str, Any]]:
    """What the Connectors page shows."""
    gmail_oauth = bool(os.getenv("GOOGLE_OAUTH_CLIENT_ID") and os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"))
    ms_oauth = bool(os.getenv("MICROSOFT_OAUTH_CLIENT_ID") and os.getenv("MICROSOFT_OAUTH_CLIENT_SECRET"))
    yahoo_env = bool(os.getenv("YAHOO_USER") and os.getenv("YAHOO_PASS"))
    gmail_env = bool(os.getenv("GMAIL_USER") and os.getenv("GMAIL_PASS"))
    outlook_env = bool(os.getenv("OUTLOOK_USER") and (os.getenv("OUTLOOK_PASSWORD") or os.getenv("OUTLOOK_PASS")))

    def _row(provider: str, mode: str, ready: bool, connected: bool, note: str,
             *, oauth_ready: bool = False) -> dict:
        return {
            "provider": provider,
            "mode": mode,
            "ready": ready,
            "connected": connected or provider in _CONNECTIONS,
            "note": note,
            "account": (_CONNECTIONS.get(provider) or {}).get("account") or "",
            "oauth_ready": oauth_ready,
            "supports_oauth": provider in ("gmail", "microsoft"),
        }

    return [
        _row("yahoo", "app_password", yahoo_env, yahoo_env,
             "Yahoo: guided app-password (IMAP). OAuth not offered by Yahoo for this path.",
             oauth_ready=False),
        _row("gmail", "oauth2", gmail_oauth or gmail_env, "gmail" in _CONNECTIONS or gmail_env,
             ("OAuth ready — click Connect OAuth." if gmail_oauth
              else "OAuth button visible; add GOOGLE_OAUTH_CLIENT_ID/SECRET to enable sign-in. "
                   "App-password form works today."),
             oauth_ready=gmail_oauth),
        _row("microsoft", "oauth2", ms_oauth or outlook_env,
             "microsoft" in _CONNECTIONS or outlook_env,
             ("OAuth ready — click Connect OAuth." if ms_oauth
              else "OAuth button visible; add MICROSOFT_OAUTH_CLIENT_ID/SECRET to enable sign-in. "
                   "App-password form works today."),
             oauth_ready=ms_oauth),
    ]


def start_oauth(provider: str, account_sub: str = "") -> dict[str, Any]:
    """Return authorize URL for Gmail or Microsoft."""
    _prune_oauth_state()
    state = secrets.token_urlsafe(24)
    redirect = f"{_public_base()}/app/connectors/callback/{provider}"
    _STATE[state] = {
        "provider": provider, "ts": time.time(),
        "account_sub": (account_sub or "").strip(),
    }

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
    _prune_oauth_state()
    meta = _STATE.pop(state, None)
    if not meta or meta.get("provider") != provider:
        return {"error": "invalid_state"}
    # Expired after prune+pop race: reject stale starts explicitly.
    if time.time() - float(meta.get("ts") or 0) > _STATE_TTL_S:
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
            access = token.get("access_token") or ""
            refresh = token.get("refresh_token") or ""
            account = _gmail_email(access) or "gmail_oauth"
            _CONNECTIONS["gmail"] = {
                "account": account,
                "refresh_token": refresh,
                "access_token": access,
                "connected_at": time.time(),
            }
            _persist_oauth(meta.get("account_sub") or "", "gmail", account, refresh, access)
            return {"ok": True, "provider": "gmail", "account": account}

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
            access = token.get("access_token") or ""
            refresh = token.get("refresh_token") or ""
            account = _microsoft_email(access, token.get("id_token")) or "microsoft_oauth"
            _CONNECTIONS["microsoft"] = {
                "account": account,
                "refresh_token": refresh,
                "access_token": access,
                "connected_at": time.time(),
            }
            _persist_oauth(meta.get("account_sub") or "", "microsoft", account, refresh, access)
            return {"ok": True, "provider": "microsoft", "account": account}
    except Exception as e:
        logger.warning("oauth finish failed: %s", e)
        return {"error": str(e)}
    return {"error": "unsupported"}


def _persist_oauth(account_sub: str, provider: str, account: str,
                   refresh: str, access: str) -> None:
    if not account_sub or not refresh or "@" not in account:
        return
    try:
        from common.mailbox_store import upsert_oauth
        upsert_oauth(
            account_sub=account_sub, provider=provider,
            account_email=account, refresh_token=refresh, access_token=access,
        )
    except Exception as e:
        logger.warning("persist oauth mailbox failed: %s", e)


def _gmail_email(access_token: str) -> str:
    if not access_token:
        return ""
    try:
        info = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        ).json()
        return str(info.get("email") or "").strip()
    except Exception:
        return ""


def _microsoft_email(access_token: str, id_token: Any) -> str:
    if id_token and isinstance(id_token, str) and id_token.count(".") == 2:
        try:
            import base64
            import json
            pad = "=" * (-len(id_token.split(".")[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(id_token.split(".")[1] + pad))
            email = str(payload.get("email") or payload.get("preferred_username") or "").strip()
            if email:
                return email
        except Exception as e:
            logger.debug("microsoft id_token parse failed: %s", e)
    if not access_token:
        return ""
    try:
        info = requests.get(
            "https://graph.microsoft.com/oidc/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        ).json()
        return str(info.get("email") or info.get("preferred_username") or "").strip()
    except Exception:
        return ""


def refresh_gmail_access(refresh_token: str) -> str:
    """Return a fresh access token, or empty string (fail open)."""
    if not (refresh_token or "").strip():
        return ""
    try:
        data = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
                "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
                "refresh_token": refresh_token.strip(),
                "grant_type": "refresh_token",
            },
            timeout=15,
        ).json()
        return str(data.get("access_token") or "")
    except Exception as e:
        logger.warning("gmail refresh failed: %s", e)
        return ""


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
