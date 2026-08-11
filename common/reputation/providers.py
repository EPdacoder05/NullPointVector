"""
Concrete reputation providers.

Each commercial feed is gated on an env var holding its API key — absent key →
`enabled` is False → the aggregator silently skips it. This lets us ship the whole
hybrid pipeline now and "light up" each vendor by dropping a key in the
environment, with zero code change.

    Provider        env key                    notes
    --------        -------                    -----
    local           (none — always on)         our own observed-threat history
    ftc             FTC_DNC_API_KEY            FTC robocall/DNC complaint data
    nomorobo        NOMOROBO_API_KEY           robocall blocklist
    hiya            HIYA_API_KEY / HIYA_TOKEN  caller-id + spam scoring
    truecaller      TRUECALLER_API_KEY         crowd spam tags
    robokiller      ROBOKILLER_API_KEY         scam/robocall feed
    ipqs (phone)    IPQS_API_KEY               phone validation / fraud score
    ipqs_email      IPQS_API_KEY               sender email verification (phish)
    ipqs_url        IPQS_API_KEY               malicious URL scan (smish)

Phone providers register in `_PROVIDER_CLASSES` (aggregator fan-out).
Email/URL enrichment providers register in `_ENRICHMENT_CLASSES` (called on-demand
from phish/smish paths via `common.reputation.intel`).

To add a phone vendor: subclass `_HTTPProvider` or `ReputationProvider`, set
`name`/`env_key`, implement `_parse`, register in `_PROVIDER_CLASSES`.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from common.reputation.base import ReputationProvider, ReputationScore, Verdict

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- local
class LocalThreatDBProvider(ReputationProvider):
    """Score a number against threats WE have already confirmed + stored.

    This is the always-on baseline: every vishing/smishing detection the platform
    makes is persisted with its sender/caller_id, so a number that burned one user
    is instantly known for the next. No external dependency, no key, no cost.
    """
    name = "local"
    weight = 1.0

    @property
    def enabled(self) -> bool:
        return os.getenv("REPUTATION_LOCAL_DISABLED", "").lower() not in ("1", "true")

    def _lookup(self, number: str) -> Optional[ReputationScore]:
        try:
            from Autobot.VectorDB.NullPoint_Vector import get_threats_by_sender
        except Exception:
            # helper not present in this build → degrade gracefully (no local hits)
            return None
        rows = get_threats_by_sender(number, limit=50) or []
        if not rows:
            return None
        n = len(rows)
        cats = sorted({(r.get("metadata", {}) or {}).get("channel", "vishing") for r in rows})
        # more independent sightings → higher risk, saturating
        risk = min(0.95, 0.5 + 0.1 * n)
        return ReputationScore(
            number=number, risk=risk, verdict=Verdict.FRAUD if risk >= 0.75 else Verdict.SPAM,
            categories=cats + ["prior_offender"], sources=[self.name],
            report_count=n, confidence=min(1.0, 0.5 + 0.1 * n),
            raw={"sightings": n},
        )


# ----------------------------------------------------------------------- HTTP base
class _HTTPProvider(ReputationProvider):
    """Shared skeleton for keyed HTTP reputation feeds.

    Subclasses set `name`, `env_key`, `base_url` and implement `_parse(json)`.
    The actual request is centralized here (timeout, auth header, error handling).
    """
    env_key: str = ""
    base_url: str = ""
    weight = 1.5  # commercial feeds weighted above the free baseline

    @property
    def api_key(self) -> str:
        return os.getenv(self.env_key, "").strip()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.base_url)

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}

    def _params(self, number: str) -> dict:
        return {"number": number}

    def _lookup(self, number: str) -> Optional[ReputationScore]:
        import requests  # lazy: keep import cost off the no-key path
        timeout = float(os.getenv("REPUTATION_HTTP_TIMEOUT", "3.0"))
        resp = requests.get(self.base_url, headers=self._headers(),
                            params=self._params(number), timeout=timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return self._parse(number, resp.json())

    def _parse(self, number: str, data: dict) -> Optional[ReputationScore]:  # pragma: no cover
        raise NotImplementedError


# ------------------------------------------------------------------- vendor impls
class FTCProvider(_HTTPProvider):
    """FTC robocall / Do-Not-Call complaint signal (free baseline feed).

    The FTC publishes complaint datasets; wire `FTC_DNC_BASE_URL` to your ingest
    endpoint (or a local mirror). Risk scales with complaint volume.
    """
    name = "ftc"
    env_key = "FTC_DNC_API_KEY"
    weight = 1.2

    @property
    def base_url(self) -> str:
        return os.getenv("FTC_DNC_BASE_URL", "")

    def _parse(self, number: str, data: dict) -> Optional[ReputationScore]:
        complaints = int(data.get("complaint_count", data.get("count", 0)) or 0)
        if complaints <= 0:
            return None
        risk = min(0.9, 0.3 + 0.05 * complaints)
        topic = data.get("topic") or data.get("subject") or "robocall"
        return ReputationScore(
            number=number, risk=risk, categories=[str(topic).lower(), "ftc_complaint"],
            sources=[self.name], report_count=complaints, raw=data)


class NomoroboProvider(_HTTPProvider):
    name = "nomorobo"
    env_key = "NOMOROBO_API_KEY"

    @property
    def base_url(self) -> str:
        return os.getenv("NOMOROBO_BASE_URL", "")

    def _parse(self, number: str, data: dict) -> Optional[ReputationScore]:
        blocked = bool(data.get("blocked") or data.get("is_robocall"))
        score = data.get("score")
        risk = float(score) if score is not None else (0.85 if blocked else 0.0)
        if risk <= 0:
            return None
        return ReputationScore(
            number=number, risk=min(1.0, risk), categories=["robocall"],
            sources=[self.name], raw=data)


class HiyaProvider(_HTTPProvider):
    name = "hiya"
    env_key = "HIYA_API_KEY"

    @property
    def api_key(self) -> str:
        return os.getenv(self.env_key, os.getenv("HIYA_TOKEN", "")).strip()

    @property
    def base_url(self) -> str:
        return os.getenv("HIYA_BASE_URL", "")

    def _parse(self, number: str, data: dict) -> Optional[ReputationScore]:
        # Hiya-style: category in {spam, fraud, neutral}, reputationScore 0..1
        cat = str(data.get("category", data.get("reputation", "neutral"))).lower()
        score = data.get("reputationScore", data.get("score"))
        risk = float(score) if score is not None else {"fraud": 0.9, "spam": 0.6}.get(cat, 0.0)
        if risk <= 0:
            return None
        return ReputationScore(
            number=number, risk=min(1.0, risk), categories=[cat],
            sources=[self.name], raw=data)


class TruecallerProvider(_HTTPProvider):
    name = "truecaller"
    env_key = "TRUECALLER_API_KEY"

    @property
    def base_url(self) -> str:
        return os.getenv("TRUECALLER_BASE_URL", "")

    def _parse(self, number: str, data: dict) -> Optional[ReputationScore]:
        spam_score = data.get("spamScore", data.get("spam_score"))
        reports = int(data.get("spamReports", data.get("reports", 0)) or 0)
        risk = float(spam_score) / 100.0 if spam_score is not None else min(0.9, 0.1 * reports)
        if risk <= 0:
            return None
        tags = [str(t).lower() for t in (data.get("tags") or [])] or ["spam"]
        return ReputationScore(
            number=number, risk=min(1.0, risk), categories=tags,
            sources=[self.name], report_count=reports, raw=data)


class RobokillerProvider(_HTTPProvider):
    name = "robokiller"
    env_key = "ROBOKILLER_API_KEY"

    @property
    def base_url(self) -> str:
        return os.getenv("ROBOKILLER_BASE_URL", "")

    def _parse(self, number: str, data: dict) -> Optional[ReputationScore]:
        cat = str(data.get("category", "")).lower()
        is_scam = bool(data.get("is_scam") or cat in ("scam", "fraud"))
        risk = 0.92 if is_scam else (0.6 if data.get("is_spam") else 0.0)
        if risk <= 0:
            return None
        return ReputationScore(
            number=number, risk=risk, categories=[cat or ("scam" if is_scam else "spam")],
            sources=[self.name], raw=data)


def _ipqs_api_key() -> str:
    return os.getenv("IPQS_API_KEY", "").strip()


def _is_reputation_strict() -> bool:
    """When true, surface provider failures instead of silent fail-open."""
    return os.getenv("REPUTATION_STRICT", "").lower() in ("1", "true", "yes")


def _ipqs_fetch(api_type: str, value: str) -> Optional[dict]:
    """Shared IPQS key-in-URL GET. Returns JSON body or None (fail-open unless strict)."""
    import urllib.parse
    import requests
    key = _ipqs_api_key()
    if not key or not value:
        return None
    url = (
        f"https://www.ipqualityscore.com/api/json/{api_type}/"
        f"{urllib.parse.quote(key, safe='')}/{urllib.parse.quote(value, safe='')}"
    )
    timeout = float(os.getenv("REPUTATION_HTTP_TIMEOUT", "3.0"))
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("success"):
            msg = str(data.get("message") or "IPQS request failed")
            logger.warning("ipqs %s: %s", api_type, msg)
            if _is_reputation_strict():
                return {"success": False, "message": msg, "_provider": "ipqs", "_type": api_type}
            return None
        return data
    except Exception as exc:
        logger.warning("ipqs %s lookup error: %s", api_type, exc)
        if _is_reputation_strict():
            return {"success": False, "message": str(exc), "_provider": "ipqs", "_type": api_type}
        return None


class IPQSPhoneProvider(ReputationProvider):
    """IPQualityScore phone validation — key-in-URL auth (not Bearer).

    Set IPQS_API_KEY in the environment. Returns fraud_score (0–100), line type,
    VOIP flags, and carrier metadata. Disabled automatically when the key is absent
    or the account is out of credits (`success: false` in the JSON body).
    """
    name = "ipqs"
    env_key = "IPQS_API_KEY"
    weight = 1.4

    @property
    def api_key(self) -> str:
        return _ipqs_api_key()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _lookup(self, number: str) -> Optional[ReputationScore]:
        clean = "".join(c for c in number if c.isdigit() or c == "+")
        if not clean:
            return None
        data = _ipqs_fetch("phone", clean)
        if not data:
            return None
        if not data.get("success"):
            return ReputationScore(
                number=number, verdict=Verdict.UNKNOWN,
                categories=["provider_error"], sources=[self.name],
                raw={"provider_error": data.get("message"), "provider": "ipqs", "strict": True},
            )
        return self._parse(number, data)

    def _parse(self, number: str, data: dict) -> Optional[ReputationScore]:
        fraud = data.get("fraud_score")
        risk = float(fraud) / 100.0 if fraud is not None else 0.0
        if data.get("spammer"):
            risk = max(risk, 0.75)
        if data.get("risky"):
            risk = max(risk, 0.55)
        if data.get("VOIP") and risk < 0.4:
            risk = max(risk, 0.35)
        if risk <= 0:
            return None
        cats = []
        if data.get("spammer"):
            cats.append("spammer")
        if data.get("VOIP"):
            cats.append("voip")
        if data.get("prepaid"):
            cats.append("prepaid")
        line = str(data.get("line_type") or data.get("line_type_name") or "").lower()
        if line:
            cats.append(line)
        verdict = Verdict.FRAUD if risk >= 0.75 else (Verdict.SPAM if risk >= 0.45 else Verdict.NEUTRAL)
        return ReputationScore(
            number=number, risk=min(1.0, risk), verdict=verdict,
            categories=cats or ["phone_intel"], sources=[self.name],
            confidence=min(1.0, 0.5 + risk / 2), raw=data,
        )


class IPQSEmailProvider:
    """IPQS email verification for phish sender enrichment (not phone aggregator)."""
    name = "ipqs_email"
    env_key = "IPQS_API_KEY"

    @property
    def enabled(self) -> bool:
        return bool(_ipqs_api_key())

    def check(self, email: str) -> Optional[dict]:
        if not self.enabled or not email or "@" not in email:
            return None
        data = _ipqs_fetch("email", email.strip().lower())
        if not data or not data.get("success"):
            if data:
                logger.debug("ipqs email: %s", data.get("message"))
            return None
        fraud = data.get("fraud_score")
        risk = float(fraud) / 100.0 if fraud is not None else 0.0
        if data.get("recent_abuse"):
            risk = max(risk, 0.7)
        if data.get("disposable"):
            risk = max(risk, 0.55)
        if risk <= 0:
            return None
        return {"risk": min(1.0, risk), "fraud_score": fraud, "source": self.name, "raw": data}


class IPQSURLProvider:
    """IPQS malicious URL scan for smish link enrichment (not phone aggregator)."""
    name = "ipqs_url"
    env_key = "IPQS_API_KEY"

    @property
    def enabled(self) -> bool:
        return bool(_ipqs_api_key())

    def check(self, url: str) -> Optional[dict]:
        if not self.enabled or not url:
            return None
        data = _ipqs_fetch("url", url.strip())
        if not data or not data.get("success"):
            if data:
                logger.debug("ipqs url: %s", data.get("message"))
            return None
        score = data.get("risk_score", data.get("fraud_score"))
        risk = float(score) / 100.0 if score is not None else 0.0
        if data.get("phishing"):
            risk = max(risk, 0.8)
        if data.get("malware"):
            risk = max(risk, 0.85)
        if risk <= 0:
            return None
        return {"risk": min(1.0, risk), "risk_score": score, "source": self.name, "raw": data}


def check_urlhaus(url: str) -> Optional[dict]:
    """URLhaus malware URL lookup. Uses URLHAUS_AUTH_KEY; fail-open on error."""
    import requests
    key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    if not key or not url:
        return None
    timeout = float(os.getenv("REPUTATION_HTTP_TIMEOUT", "3.0"))
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url.strip()},
            headers={"Auth-Key": key},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.debug("urlhaus lookup error: %s", exc)
        return None
    status = data.get("query_status", "")
    if status == "no_results":
        return {"listed": False, "source": "urlhaus", "raw": data}
    if status != "ok":
        logger.debug("urlhaus: %s", status)
        return None
    return {"listed": True, "threat": data.get("threat"), "source": "urlhaus", "raw": data}


_PROVIDER_CLASSES = [
    LocalThreatDBProvider,
    FTCProvider,
    NomoroboProvider,
    HiyaProvider,
    TruecallerProvider,
    RobokillerProvider,
    IPQSPhoneProvider,
]

_ENRICHMENT_CLASSES = [
    IPQSEmailProvider,
    IPQSURLProvider,
]


def default_providers() -> list[ReputationProvider]:
    """Instantiate all providers; the aggregator filters to the enabled ones."""
    return [cls() for cls in _PROVIDER_CLASSES]


def enabled_provider_names() -> list[str]:
    return [p.name for p in default_providers() if p.enabled]
