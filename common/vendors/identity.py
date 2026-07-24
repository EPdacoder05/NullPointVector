"""
Outsourced identity / credit / OSINT vendors — do NOT reinvent bureaus.

NullPoint never builds a credit bureau or bank-link UI. We call licensed APIs:

  Layer              Vendor(s)                         Env keys
  -----------------  --------------------------------  -------------------------
  Bank + KYC IDV     Plaid Identity / IDV              PLAID_CLIENT_ID, PLAID_SECRET
  Cash-flow credit   Plaid Check (optional, FCRA)      same Plaid keys + product enable
  Traditional score  Array (or Experian/TU partner)    ARRAY_API_KEY / CREDIT_PARTNER_API_KEY
  Breach / dark-web  IPQS leaked-data (licensed)       IPQS_API_KEY
  Phone / email risk IPQS phone + email                IPQS_API_KEY

Plaid alone is NOT a FICO bureau replacement. Use Plaid for:
  - "is this person who they say" (IDV / data-source match)
  - bank-linked identity + optional cash-flow underwriting (Plaid Check)

Use Array (or another bureau reseller) for consumer credit scores / monitoring.
All calls are consent-gated and fail-open.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = float(os.getenv("VENDOR_HTTP_TIMEOUT", "8.0"))


@dataclass
class VendorReport:
    layer: str
    vendor: str
    subject: str
    risk: float = 0.0
    findings: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    ok: bool = True
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "vendor": self.vendor,
            "subject": self.subject,
            "risk": round(self.risk, 4),
            "findings": self.findings,
            "ok": self.ok,
            "error": self.error,
        }


# --------------------------------------------------------------------------- Plaid
def _plaid_base() -> str:
    env = (os.getenv("PLAID_ENV") or "sandbox").lower()
    return {
        "sandbox": "https://sandbox.plaid.com",
        "development": "https://development.plaid.com",
        "production": "https://production.plaid.com",
    }.get(env, "https://sandbox.plaid.com")


def _plaid_creds() -> Optional[tuple[str, str]]:
    cid = os.getenv("PLAID_CLIENT_ID", "").strip()
    secret = os.getenv("PLAID_SECRET", "").strip()
    return (cid, secret) if cid and secret else None


def plaid_identity_status(*, consented: bool = False) -> VendorReport:
    """Health / config check for Plaid (no user PII required)."""
    subject = "plaid_config"
    if not consented:
        return VendorReport("identity", "plaid", subject, ok=False, error="consent_required")
    creds = _plaid_creds()
    if not creds:
        return VendorReport(
            "identity", "plaid", subject, ok=False,
            error="missing_keys",
            findings=["Set PLAID_CLIENT_ID + PLAID_SECRET (sandbox first)"],
        )
    # Lightweight institutions get — proves keys work without Link session.
    try:
        r = requests.post(
            f"{_plaid_base()}/institutions/get",
            json={
                "client_id": creds[0], "secret": creds[1],
                "count": 1, "offset": 0, "country_codes": ["US"],
            },
            timeout=_TIMEOUT,
        )
        data = r.json() if r.content else {}
        if r.status_code >= 400:
            return VendorReport(
                "identity", "plaid", subject, ok=False,
                error=data.get("error_message") or data.get("error_code") or r.reason,
                raw=data, findings=["Plaid keys rejected or product not enabled"],
            )
        return VendorReport(
            "identity", "plaid", subject, risk=0.0, ok=True, raw={"status": "reachable"},
            findings=[
                "Plaid reachable — use Link + /identity/get or Identity Verification in-app",
                "Not a FICO score; pair with Array/bureau partner for credit monitoring",
            ],
        )
    except Exception as e:
        logger.warning("plaid status failed: %s", e)
        return VendorReport("identity", "plaid", subject, ok=False, error=str(e))


def plaid_identity_get(access_token: str, *, consented: bool = False) -> VendorReport:
    """Fetch bank-linked identity for a Plaid Item (after Link)."""
    subject = "plaid_item"
    if not consented:
        return VendorReport("identity", "plaid", subject, ok=False, error="consent_required")
    creds = _plaid_creds()
    if not creds or not access_token:
        return VendorReport(
            "identity", "plaid", subject, ok=False,
            error="missing_keys_or_token",
            findings=["Need PLAID_* keys and a user access_token from Link"],
        )
    try:
        r = requests.post(
            f"{_plaid_base()}/identity/get",
            json={"client_id": creds[0], "secret": creds[1], "access_token": access_token},
            timeout=_TIMEOUT,
        )
        data = r.json() if r.content else {}
        if r.status_code >= 400:
            return VendorReport(
                "identity", "plaid", subject, ok=False,
                error=data.get("error_message") or data.get("error_code"),
                raw=data,
            )
        accounts = data.get("accounts") or []
        names = []
        for acct in accounts:
            for owner in acct.get("owners") or []:
                names.extend(n.get("data") or n.get("full_name") or "" for n in (owner.get("names") or []))
        findings = [f"Bank-linked owners: {', '.join(x for x in names if x) or 'present'}"]
        return VendorReport(
            "identity", "plaid", subject, risk=0.1, findings=findings, raw=data, ok=True,
        )
    except Exception as e:
        logger.warning("plaid identity/get failed: %s", e)
        return VendorReport("identity", "plaid", subject, ok=False, error=str(e))


# --------------------------------------------------------------- Credit partner
def _credit_partner_config() -> tuple[str, str, str]:
    """Return (vendor_name, api_key, base_url).

    Prefer Array; fall back to generic CREDIT_PARTNER_* so Experian/TU resellers
    can plug in without code changes.
    """
    array_key = os.getenv("ARRAY_API_KEY", "").strip()
    if array_key:
        base = os.getenv("ARRAY_BASE_URL", "https://sandbox.array.io").rstrip("/")
        return "array", array_key, base
    key = os.getenv("CREDIT_PARTNER_API_KEY", "").strip()
    base = os.getenv("CREDIT_PARTNER_BASE_URL", "").rstrip("/")
    name = os.getenv("CREDIT_PARTNER_NAME", "credit_partner").strip() or "credit_partner"
    return name, key, base


def credit_score_lookup(
    user_token_or_id: str,
    *,
    consented: bool = False,
    soft_pull: bool = True,
) -> VendorReport:
    """Licensed consumer credit score / monitoring via Array (or partner).

    Array is the default consumer-app path (soft-pull monitoring). Swap to
    Experian/TransUnion reseller by setting CREDIT_PARTNER_* instead of ARRAY_*.
    """
    subject = user_token_or_id.strip()
    layer = "credit"
    if not consented:
        return VendorReport(layer, "credit", subject, ok=False, error="consent_required")
    vendor, key, base = _credit_partner_config()
    if not key or not base:
        return VendorReport(
            layer, vendor or "credit", subject, ok=False, error="missing_keys",
            findings=[
                "Set ARRAY_API_KEY (+ optional ARRAY_BASE_URL) for consumer credit",
                "Or CREDIT_PARTNER_API_KEY + CREDIT_PARTNER_BASE_URL for bureau reseller",
                "Plaid does not replace this layer",
            ],
        )
    # Array-style: GET score by user — path is partner-specific; keep fail-open.
    path = os.getenv(
        "CREDIT_PARTNER_SCORE_PATH",
        f"/api/user/{quote(subject, safe='')}/credit-score",
    )
    headers = {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "X-Soft-Pull": "1" if soft_pull else "0",
    }
    try:
        r = requests.get(f"{base}{path}", headers=headers, timeout=_TIMEOUT)
        data = r.json() if r.content else {}
        if r.status_code >= 400:
            return VendorReport(
                layer, vendor, subject, ok=False,
                error=str(data.get("message") or data.get("error") or r.reason),
                raw=data,
                findings=["Credit partner rejected request — check sandbox keys / user id"],
            )
        score = data.get("score") or data.get("creditScore") or data.get("fico")
        findings = []
        risk = 0.0
        if score is not None:
            try:
                s = float(score)
                findings.append(f"Credit score on file: {int(s)}")
                # Lower score → higher fraud/abuse risk for our product signal only.
                risk = max(0.0, min(0.85, (700 - s) / 400))
            except (TypeError, ValueError):
                findings.append("Score payload present (unparsed)")
        else:
            findings.append("Partner responded — no numeric score in payload")
        if soft_pull:
            findings.append("Soft-pull path (monitoring-friendly)")
        return VendorReport(layer, vendor, subject, risk=risk, findings=findings, raw=data, ok=True)
    except Exception as e:
        logger.warning("credit partner failed: %s", e)
        return VendorReport(layer, vendor, subject, ok=False, error=str(e))


# ----------------------------------------------------------------- Breach OSINT
def breach_exposure(email_or_phone: str, *, consented: bool = False) -> VendorReport:
    """Licensed breach / dark-web exposure (IPQS) — not DIY scraping."""
    subject = email_or_phone.strip()
    layer = "osint"
    if not consented or not subject:
        return VendorReport(layer, "ipqs", subject, ok=False, error="consent_required")
    key = os.getenv("IPQS_API_KEY", "").strip()
    if not key:
        return VendorReport(
            layer, "ipqs", subject, ok=False, error="missing_keys",
            findings=["Set IPQS_API_KEY for licensed leak lookups"],
        )
    try:
        from common.reputation.providers import _ipqs_fetch
        data = _ipqs_fetch("leaked", subject) or {}
        if not data.get("success"):
            return VendorReport(
                layer, "ipqs", subject, ok=False,
                error=str(data.get("message") or "unavailable"),
                raw=data,
            )
        exposed = bool(data.get("exposed") or data.get("leaked") or data.get("breach"))
        return VendorReport(
            layer, "ipqs", subject,
            risk=0.7 if exposed else 0.05,
            findings=(
                ["Identifier appears in licensed breach intelligence"]
                if exposed else ["No licensed breach hits"]
            ),
            raw=data, ok=True,
        )
    except Exception as e:
        logger.warning("breach_exposure failed: %s", e)
        return VendorReport(layer, "ipqs", subject, ok=False, error=str(e))


def phone_reputation(number: str, *, consented: bool = False) -> VendorReport:
    """IPQS phone validation — primary signal when subject is a phone number."""
    subject = number.strip()
    layer = "phone"
    if not consented or not subject:
        return VendorReport(layer, "ipqs", subject, ok=False, error="consent_required")
    digits = "".join(c for c in subject if c.isdigit() or c == "+")
    if len(digits) < 10:
        return VendorReport(layer, "ipqs", subject, ok=False, error="not_a_phone")
    key = os.getenv("IPQS_API_KEY", "").strip()
    if not key:
        return VendorReport(
            layer, "ipqs", subject, ok=False, error="missing_keys",
            findings=["Set IPQS_API_KEY for phone reputation"],
        )
    try:
        from common.reputation.providers import _ipqs_fetch
        data = _ipqs_fetch("phone", digits) or {}
        if not data.get("success"):
            return VendorReport(
                layer, "ipqs", subject, ok=False,
                error=str(data.get("message") or "unavailable"),
                raw=data,
                findings=["IPQS phone lookup failed — check credits / key"],
            )
        fraud = data.get("fraud_score")
        risk = float(fraud) / 100.0 if fraud is not None else 0.0
        findings = []
        if fraud is not None:
            findings.append(f"Fraud score: {fraud}/100")
        if data.get("VOIP"):
            findings.append("Line type: VOIP")
            risk = max(risk, 0.35)
        if data.get("spammer"):
            findings.append("Flagged as spammer")
            risk = max(risk, 0.75)
        if data.get("risky"):
            findings.append("Marked risky by IPQS")
        carrier = data.get("carrier") or data.get("company")
        if carrier:
            findings.append(f"Carrier: {carrier}")
        line = data.get("line_type") or data.get("line_type_name")
        if line:
            findings.append(f"Line: {line}")
        country = data.get("country") or data.get("region")
        if country:
            findings.append(f"Region: {country}")
        if not findings:
            findings.append("Phone scored — no extra flags")
        return VendorReport(
            layer, "ipqs", subject, risk=min(1.0, risk),
            findings=findings, raw=data, ok=True,
        )
    except Exception as e:
        logger.warning("phone_reputation failed: %s", e)
        return VendorReport(layer, "ipqs", subject, ok=False, error=str(e))


def _looks_like_phone(subject: str) -> bool:
    digits = "".join(c for c in subject if c.isdigit())
    return len(digits) >= 10 and "@" not in subject


def enrich_identity_bundle(
    *,
    subject: str,
    consented: bool = False,
    plaid_access_token: Optional[str] = None,
    credit_user_id: Optional[str] = None,
) -> dict[str, Any]:
    """Run the full outsourced stack. Fail-open per layer."""
    if not consented:
        return {"error": "consent_required", "reports": []}
    subject = subject.strip()
    reports: list[VendorReport] = []

    # Phone path first when the subject is a number (what you type on Credit & OSINT).
    if _looks_like_phone(subject):
        reports.append(phone_reputation(subject, consented=True))
        reports.append(breach_exposure(subject, consented=True))
        # Credit partners usually need a user token — still attempt / surface config.
        reports.append(credit_score_lookup(credit_user_id or subject, consented=True))
    else:
        if plaid_access_token:
            reports.append(plaid_identity_get(plaid_access_token, consented=True))
        else:
            reports.append(plaid_identity_status(consented=True))
        reports.append(credit_score_lookup(credit_user_id or subject, consented=True))
        reports.append(breach_exposure(subject, consented=True))
        # Email risk via IPQS when subject is an email
        if "@" in subject:
            try:
                from common.reputation.providers import _ipqs_fetch
                data = _ipqs_fetch("email", subject.lower()) or {}
                if data.get("success"):
                    fraud = data.get("fraud_score")
                    risk = float(fraud) / 100.0 if fraud is not None else 0.0
                    findings = [f"Email fraud score: {fraud}"] if fraud is not None else []
                    if data.get("disposable"):
                        findings.append("Disposable mailbox")
                        risk = max(risk, 0.6)
                    if data.get("recent_abuse"):
                        findings.append("Recent abuse")
                        risk = max(risk, 0.55)
                    reports.append(VendorReport(
                        "email", "ipqs", subject, risk=risk,
                        findings=findings or ["Email reputation returned"],
                        raw=data, ok=True,
                    ))
                else:
                    reports.append(VendorReport(
                        "email", "ipqs", subject, ok=False,
                        error=str(data.get("message") or "unavailable"), raw=data,
                    ))
            except Exception as e:
                reports.append(VendorReport("email", "ipqs", subject, ok=False, error=str(e)))

    return {
        "subject": subject,
        "consented": True,
        "layers": {
            "phone": "IPQS phone validation (fraud_score, VOIP, carrier)",
            "plaid": "identity / IDV / optional Plaid Check cash-flow",
            "credit": "Array or CREDIT_PARTNER_* bureau reseller",
            "osint": "IPQS licensed leak feed",
            "email": "IPQS email verification",
        },
        "reports": [r.to_dict() for r in reports],
    }
