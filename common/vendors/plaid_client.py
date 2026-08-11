"""
Outsourced identity + credit signals via Plaid (do not reinvent).

What we use Plaid for (licensed, FCRA-aware products — not a home-grown bureau):
  - Identity Verification (IDV)  → KYC / Trust Index fraud risk
  - Identity (bank-linked)       → name/phone/address ownership signals
  - Plaid Check Consumer Report  → cash-flow / LendScore underwriting signals
    (when PLAID_CHECK_ENABLED=true and product access is approved)

What we do NOT build ourselves:
  - Credit bureau scrapers, FICO engines, or illegal breach dumps

Env:
  PLAID_CLIENT_ID=
  PLAID_SECRET=
  PLAID_ENV=sandbox|development|production   (default sandbox)
  PLAID_IDV_TEMPLATE_ID=                     (Dashboard template for IDV)
  PLAID_CHECK_ENABLED=false                  (opt-in Consumer Report path)

Docs: https://plaid.com/docs/identity-verification/
      https://plaid.com/docs/check/
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _base_url() -> str:
    env = os.getenv("PLAID_ENV", "sandbox").strip().lower()
    if env == "production":
        return "https://production.plaid.com"
    if env == "development":
        return "https://development.plaid.com"
    return "https://sandbox.plaid.com"


def _creds() -> Optional[tuple[str, str]]:
    cid = os.getenv("PLAID_CLIENT_ID", "").strip()
    secret = os.getenv("PLAID_SECRET", "").strip()
    if not cid or not secret:
        return None
    return cid, secret


def enabled() -> bool:
    return _creds() is not None


def _post(path: str, body: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Authenticated Plaid POST. Fail-open on any error."""
    import requests
    creds = _creds()
    if not creds:
        return None
    cid, secret = creds
    payload = {"client_id": cid, "secret": secret, **body}
    url = f"{_base_url()}{path}"
    timeout = float(os.getenv("PLAID_HTTP_TIMEOUT", "8.0"))
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        data = resp.json() if resp.content else {}
        if resp.status_code >= 400:
            logger.warning(
                "plaid %s -> %s: %s",
                path, resp.status_code, data.get("error_message") or data.get("error_code"),
            )
            return {"_error": True, "status": resp.status_code, **data}
        return data
    except Exception as e:
        logger.warning("plaid %s failed: %s", path, e)
        return None


def create_link_token(
    *,
    user_id: str,
    products: Optional[list[str]] = None,
    client_name: str = "NullPoint Guard",
) -> Optional[dict[str, Any]]:
    """Mint a Link token for the iOS/web client (bank connect / IDV host)."""
    products = products or ["identity"]
    body: dict[str, Any] = {
        "user": {"client_user_id": str(user_id)[:64]},
        "client_name": client_name[:30],
        "products": products,
        "country_codes": ["US"],
        "language": "en",
    }
    # IDV can be attached when a template is configured in the Dashboard.
    tmpl = os.getenv("PLAID_IDV_TEMPLATE_ID", "").strip()
    if tmpl and "identity_verification" not in products:
        body["identity_verification"] = {"template_id": tmpl}
    return _post("/link/token/create", body)


def exchange_public_token(public_token: str) -> Optional[dict[str, Any]]:
    """Exchange Link public_token → access_token (store encrypted server-side)."""
    if not public_token:
        return None
    return _post("/item/public_token/exchange", {"public_token": public_token})


def get_identity(access_token: str) -> Optional[dict[str, Any]]:
    """Bank-linked Identity product — names, emails, phones, addresses."""
    if not access_token:
        return None
    return _post("/identity/get", {"access_token": access_token})


def create_idv_session(
    *,
    client_user_id: str,
    email: Optional[str] = None,
    phone: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Start Identity Verification (KYC / Trust Index). Requires template id."""
    tmpl = os.getenv("PLAID_IDV_TEMPLATE_ID", "").strip()
    if not tmpl:
        return {"_error": True, "error_message": "PLAID_IDV_TEMPLATE_ID not set"}
    user: dict[str, Any] = {"client_user_id": str(client_user_id)[:64]}
    if email:
        user["email_address"] = email
    if phone:
        user["phone_number"] = phone
    return _post(
        "/identity_verification/create",
        {
            "template_id": tmpl,
            "gave_consent": True,
            "is_shareable": True,
            "user": user,
        },
    )


def get_idv(identity_verification_id: str) -> Optional[dict[str, Any]]:
    if not identity_verification_id:
        return None
    return _post(
        "/identity_verification/get",
        {"identity_verification_id": identity_verification_id},
    )


def summarize_idv(data: dict[str, Any]) -> dict[str, Any]:
    """Map Plaid IDV payload → NullPoint risk findings (no raw PII echo)."""
    if not data or data.get("_error"):
        return {
            "provider": "plaid",
            "ok": False,
            "findings": [data.get("error_message") or "Plaid IDV unavailable"],
            "risk": 0.0,
        }
    status = str(data.get("status") or "").lower()
    kyc = data.get("kyc_check") or {}
    risk_check = data.get("risk_check") or {}
    trust = None
    try:
        trust = (risk_check.get("trust_index") or {}).get("score")
    except Exception:
        trust = None

    findings = [f"IDV status: {status or 'unknown'}"]
    if trust is not None:
        findings.append(f"Plaid Trust Index: {trust}")
    # Higher trust → lower fraud risk for our fusion (normalize 0..100 → risk).
    risk = 0.5
    if isinstance(trust, (int, float)):
        risk = max(0.0, min(1.0, 1.0 - (float(trust) / 100.0)))
    elif status in ("success", "verified"):
        risk = 0.15
    elif status in ("failed", "expired"):
        risk = 0.85

    return {
        "provider": "plaid_idv",
        "ok": True,
        "status": status,
        "risk": round(risk, 4),
        "findings": findings,
        "kyc_summary": {k: v for k, v in kyc.items() if k in ("status", "summary")} if isinstance(kyc, dict) else {},
    }


def summarize_identity(data: dict[str, Any]) -> dict[str, Any]:
    """Bank Identity product → ownership signal (counts only, strip PII)."""
    if not data or data.get("_error"):
        return {
            "provider": "plaid_identity",
            "ok": False,
            "findings": [data.get("error_message") or "Plaid Identity unavailable"],
            "risk": 0.0,
        }
    accounts = data.get("accounts") or []
    n_email = n_phone = n_addr = 0
    for acct in accounts:
        owners = acct.get("owners") or []
        for o in owners:
            n_email += len(o.get("emails") or [])
            n_phone += len(o.get("phone_numbers") or [])
            n_addr += len(o.get("addresses") or [])
    findings = [
        f"Linked accounts: {len(accounts)}",
        f"Owner emails/phones/addresses observed: {n_email}/{n_phone}/{n_addr}",
    ]
    # Thin identity graph → slightly higher uncertainty, not auto-fraud.
    risk = 0.1 if (n_email or n_phone) else 0.35
    return {
        "provider": "plaid_identity",
        "ok": True,
        "risk": risk,
        "findings": findings,
        "account_count": len(accounts),
    }
