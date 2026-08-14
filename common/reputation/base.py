"""
Reputation core types: the normalized score, the provider contract, and the
fusion logic that combines many feeds into one verdict.

Design goals:
  - One stable schema (`ReputationScore`) regardless of which vendor answered, so
    the rest of the system never special-cases a provider.
  - Providers are dumb + isolated: each maps "its" API shape onto ReputationScore
    and nothing else. Fusion lives here, once.
  - Fail-open for availability, fail-safe for correctness: a missing/erroring
    feed lowers confidence, it never fabricates risk.
"""
from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    """Coarse, UI-ready label derived from the fused risk score."""
    FRAUD = "fraud"          # high-confidence scam/fraud number → recommend block
    SPAM = "spam"            # nuisance/robocall/telemarketer → recommend label
    NEUTRAL = "neutral"      # seen, nothing bad → allow
    UNKNOWN = "unknown"      # no feed had an opinion → allow, lower confidence


# E.164-ish normalization: keep a leading +, strip everything else to digits.
_NON_DIGITS = re.compile(r"[^\d+]")


def normalize_number(raw: str) -> str:
    """Best-effort E.164 normalization so cache keys + lookups are stable.

    Not a libphonenumber replacement — deliberately dependency-free. Assumes US
    (+1) for bare 10-digit numbers, which matches the CallKit US launch market.
    Alphanumeric sender IDs (e.g. "IRS") are returned upper-cased, unchanged.
    """
    if not raw:
        return ""
    s = raw.strip()
    if any(c.isalpha() for c in s):          # alphanumeric sender ID, not a number
        return s.upper()
    s = _NON_DIGITS.sub("", s)
    if not s:
        return ""
    if s.startswith("+"):
        return s
    digits = s
    if len(digits) == 10:                    # bare US number
        return "+1" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    return "+" + digits                      # already has country code


def directory_action_for_message(metadata: object, human_label: object = None) -> tuple[str, str]:
    """Return the safe Call Directory action for one tenant observation.

    A model prediction is useful for a warning label, but is not destructive
    evidence. Exact-number blocking requires an authenticated personal/human
    decision or an analyst/vendor-verified source. Legacy rows with no
    provenance therefore degrade to a label instead of silently blocking.
    """
    meta = metadata if isinstance(metadata, dict) else {}
    source = str(meta.get("label_source") or "").strip().lower()
    requested = str(meta.get("action") or "").strip().lower()
    try:
        risk = max(0.0, min(1.0, float(meta.get("risk_score") or 0.0)))
    except (TypeError, ValueError):
        risk = 0.0

    human_confirmed = human_label == 1 and source in {
        "human_grade", "analyst_verified",
    }
    personal_block = source == "personal_block" and requested == "block"
    corroborated = source in {"analyst_verified", "vendor_verified"} and (
        requested == "block" or risk >= 0.85
    )
    if human_confirmed or personal_block or corroborated:
        return "block", ""

    wants_warning = (
        requested in {"block", "label", "silence"}
        or risk >= 0.4
        or meta.get("is_threat") in (True, 1, "1")
        or human_label == 1
    )
    if not wants_warning:
        return "none", ""
    raw_label = meta.get("display_label") or meta.get("verdict") or "Suspicious caller"
    if isinstance(raw_label, (int, float)):
        raw_label = "Suspicious caller"
    return "label", str(raw_label).replace("_", " ").title()


@dataclass
class ReputationScore:
    """Normalized reputation result from ONE provider (or the fused aggregate)."""
    number: str
    risk: float = 0.0                        # 0.0 (clean) .. 1.0 (definitely fraud)
    verdict: Verdict = Verdict.UNKNOWN
    categories: list[str] = field(default_factory=list)  # e.g. ["robocall","irs_scam"]
    sources: list[str] = field(default_factory=list)     # provider names that reported
    report_count: int = 0                    # # of user/complaint reports, if exposed
    confidence: float = 0.0                  # how sure we are (driven by # of sources)
    raw: dict = field(default_factory=dict)  # per-provider raw payloads (debug/audit)

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "risk": round(self.risk, 4),
            "verdict": self.verdict.value,
            "categories": sorted(set(self.categories)),
            "sources": sorted(set(self.sources)),
            "report_count": self.report_count,
            "confidence": round(self.confidence, 4),
        }


class ReputationProvider(ABC):
    """One external reputation feed. Subclasses implement `_lookup` only.

    Contract:
      - `name`        : short stable id used in `sources` + config.
      - `enabled`     : False auto-disables the provider (e.g. no API key).
      - `lookup`      : public, never raises — wraps `_lookup` with a safety net.
      - `_lookup`     : provider-specific; may raise / return None freely.
    """
    name: str = "base"
    # weight in the fused score (commercial feeds tend to be higher-precision)
    weight: float = 1.0

    @property
    def enabled(self) -> bool:
        return True

    @abstractmethod
    def _lookup(self, number: str) -> Optional[ReputationScore]:
        ...

    def lookup(self, number: str) -> Optional[ReputationScore]:
        if not self.enabled:
            return None
        try:
            return self._lookup(number)
        except Exception as e:  # availability > correctness — never break screening
            logger.warning("reputation provider %s failed for %s: %s",
                           self.name, number, e)
            return None


def _verdict_for(risk: float, categories: list[str]) -> Verdict:
    fraud_cats = {"fraud", "scam", "irs_scam", "phishing", "identity_theft"}
    if risk >= 0.75 or (set(c.lower() for c in categories) & fraud_cats and risk >= 0.5):
        return Verdict.FRAUD
    if risk >= 0.4:
        return Verdict.SPAM
    if risk > 0.0:
        return Verdict.NEUTRAL
    return Verdict.UNKNOWN


def fuse(number: str, parts: list[ReputationScore]) -> ReputationScore:
    """Combine per-provider scores into one. Weighted-max with agreement boost.

    Rationale: reputation feeds are *precision* signals — one trustworthy feed
    flagging a number as IRS-scam matters even if others have never seen it. So we
    take the weighted max as the base risk, then nudge it up when multiple
    independent feeds agree (consensus → higher confidence + slightly higher risk).
    """
    parts = [p for p in parts if p is not None]
    if not parts:
        return ReputationScore(number=number, verdict=Verdict.UNKNOWN, confidence=0.0)

    base = max(p.risk for p in parts)
    n = len(parts)
    # agreement among feeds that actually saw risk
    flagged = [p for p in parts if p.risk >= 0.4]
    agreement_boost = min(0.15, 0.05 * max(0, len(flagged) - 1))
    risk = min(1.0, base + (agreement_boost if base >= 0.4 else 0.0))

    categories: list[str] = []
    sources: list[str] = []
    report_count = 0
    raw: dict = {}
    for p in parts:
        categories.extend(p.categories)
        sources.extend(p.sources or [])
        report_count += p.report_count
        if p.raw:
            raw[p.sources[0] if p.sources else "?"] = p.raw

    # confidence grows with the number of distinct sources (diminishing returns)
    confidence = min(1.0, 0.4 + 0.2 * len(set(sources)))

    return ReputationScore(
        number=number,
        risk=risk,
        verdict=_verdict_for(risk, categories),
        categories=sorted(set(categories)),
        sources=sorted(set(sources)),
        report_count=report_count,
        confidence=confidence,
        raw=raw,
    )
