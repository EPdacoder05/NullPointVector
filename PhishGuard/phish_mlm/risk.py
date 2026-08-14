"""
Unified risk assessment = supervised classifier + unsupervised anomaly layer.

Decision matrix:
    classifier=PHISH, conf ≥ 0.85                  → QUARANTINE
    classifier=PHISH, 0.70 ≤ conf < 0.85           → REVIEW
    classifier=SAFE  but anomaly ∈ {CRITICAL,EXTREME} → TRIAGE_NOVEL
        (the classifier has never seen this pattern — surface it to a human;
         the triage decision feeds the feedback buffer → next gated retrain)
    otherwise                                      → PASS

Novelty can surface unusual content for human review; it does not prove an
attack and is not automatically promoted into training data.  Latency is not
claimed here: both sparse-classifier and optional embedding performance must be
measured with the release artifact on the deployment target.
"""
import logging
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Threshold guide (kept consistent with the detector docstring).
QUARANTINE_THRESHOLD = 0.85
REVIEW_THRESHOLD = 0.70


class Action(str, Enum):
    QUARANTINE = "quarantine"
    REVIEW = "review"
    TRIAGE_NOVEL = "triage_novel"
    PASS = "pass"


@dataclass
class RiskAssessment:
    is_threat: bool
    action: Action
    risk_score: float                 # 0..1 combined risk
    classifier_pred: int
    classifier_conf: float
    anomaly_level: str
    anomaly_novelty: float
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["action"] = self.action.value
        return d


def assess(email_data: dict, detector=None, use_anomaly: bool = True,
           anomaly_detector=None) -> RiskAssessment:
    """
    Produce a unified verdict for one message. Fail-safe: any failure degrades to
    the classifier-only path, and a total failure returns PASS (assume safe).

    anomaly_detector: an explicit per-channel detector (SMS/voice). When None and
    use_anomaly is True, the default EMAIL manifold is used (load-only).
    """
    if detector is None:
        from phishing_detector import detector as detector  # singleton

    pred, conf = detector.predict(email_data)
    reasons: List[str] = []

    # Optional external intel (IPQS email / URL) — fail-open, never blocks alone.
    intel_bump = 0.0
    try:
        sender = email_data.get("from") or email_data.get("sender") or ""
        if "@" in sender:
            from common.reputation.intel import check_email_intel
            hit = check_email_intel(sender)
            if hit and hit.get("risk", 0) >= 0.45:
                intel_bump = max(intel_bump, hit["risk"] * 0.25)
                reasons.append(f"sender email flagged by {hit.get('source', 'intel')} "
                               f"(fraud score {hit.get('fraud_score', '?')})")
        body = email_data.get("body") or email_data.get("transcript") or ""
        if body:
            from utils.url_utils import extract_urls
            from common.reputation.intel import scan_url_external
            for u in extract_urls(body)[:2]:
                uhit = scan_url_external(u)
                if uhit and uhit.get("risk", 0) >= 0.5:
                    intel_bump = max(intel_bump, uhit["risk"] * 0.3)
                    reasons.append(f"link flagged by {uhit.get('source', 'intel')}")
                    break
    except Exception as e:
        logger.debug("external intel skipped: %s", e)

    level, novelty = "NORMAL", 0.0
    # Anomaly gating: skip the ~30ms MiniLM embed on obvious verdicts.
    # O(1) classifier-only fast path for high-confidence cases; O(embed) only
    # in the gray zone where novelty detection adds value.
    _CONFIDENT_SAFE = 0.92
    run_anomaly = use_anomaly and not (
        (pred == 1 and conf >= QUARANTINE_THRESHOLD) or
        (pred == 0 and conf >= _CONFIDENT_SAFE)
    )
    if run_anomaly:
        try:
            det = anomaly_detector
            if det is None:
                from anomaly.embedding_anomaly import get_anomaly_detector
                # Load-only on the hot path: never trigger a fit inside a request.
                det = get_anomaly_detector(allow_fit=False)
            if det is not None:
                result = det.score(email_data)
                level, novelty = result.level.value, result.novelty
                if result.is_anomalous:
                    reasons.append(result.explanation)
        except Exception as e:
            logger.warning(f"anomaly layer unavailable ({e}); classifier-only verdict")

    # --- decision matrix ---
    if pred == 1 and conf >= QUARANTINE_THRESHOLD:
        action, is_threat = Action.QUARANTINE, True
        reasons.append(f"classifier PHISH @ {conf:.0%} ≥ {QUARANTINE_THRESHOLD:.0%}")
    elif level == "EXTREME":
        # Unsupervised novelty is not a malicious label.  It may only request
        # review; it must never quarantine/block by itself.
        action, is_threat = Action.TRIAGE_NOVEL, False
        reasons.append("unusual pattern — human review required")
    elif pred == 1 and conf >= REVIEW_THRESHOLD:
        action, is_threat = Action.REVIEW, True
        reasons.append(f"classifier PHISH @ {conf:.0%} (review band)")
    elif pred == 0 and level == "CRITICAL":
        action, is_threat = Action.TRIAGE_NOVEL, False
        reasons.append("classifier says SAFE but pattern is novel — human triage")
    elif pred == 1:
        action, is_threat = Action.REVIEW, True
        reasons.append(f"classifier PHISH @ {conf:.0%}")
    else:
        action, is_threat = Action.PASS, False
        reasons.append("no threat signal")

    # Combined risk: phish confidence dominates; novelty contributes when safe.
    phish_component = conf if pred == 1 else 0.0
    risk_score = float(max(phish_component, 0.6 * novelty, intel_bump))

    return RiskAssessment(
        is_threat=is_threat, action=action, risk_score=round(risk_score, 4),
        classifier_pred=pred, classifier_conf=round(conf, 4),
        anomaly_level=level, anomaly_novelty=round(novelty, 4), reasons=reasons,
    )
