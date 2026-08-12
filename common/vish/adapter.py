"""
Hybrid VishGuard screening: fuse the reputation (number) path and the
transcription (content) path into one CallKit action.

    CallEvent
       │
       ├─ reputation path  (always)  ── score_number(caller_id) ─┐
       │                                                          ├─ fuse ─▶ ScreenResult
       └─ transcription path (if transcript) ── VishGuard model ─┘

Fusion principles:
  - The number path is a precision signal (a known-fraud number is fraud even on a
    benign-sounding pitch). The content path catches NEW numbers running known
    scripts. Either firing strongly is enough → we take a risk-max, then apply
    trust adjustments (known contact, STIR/SHAKEN attestation).
  - Output is one of four CallKit actions plus consumer-readable reasons (reuses
    the same explainability philosophy as the web console).
"""
from __future__ import annotations

import logging

from common.reputation import score_number
from common.reputation.base import Verdict
from common.vish.contract import CallEvent, CallKitAction, ScreenResult

logger = logging.getLogger(__name__)

# Action thresholds on the fused 0..1 risk. Tunable via the gate/eval later.
_BLOCK_AT = 0.85
_SILENCE_AT = 0.60
_LABEL_AT = 0.40


def _action_for(risk: float, *, contact_known: bool) -> CallKitAction:
    # A number in the user's own contacts is never auto-blocked/silenced — at most
    # labeled — to keep false positives from hiding legitimate, important calls.
    if contact_known:
        return CallKitAction.LABEL if risk >= _SILENCE_AT else CallKitAction.ALLOW
    if risk >= _BLOCK_AT:
        return CallKitAction.BLOCK
    if risk >= _SILENCE_AT:
        return CallKitAction.SILENCE
    if risk >= _LABEL_AT:
        return CallKitAction.LABEL
    return CallKitAction.ALLOW


def _label_for(verdict: str, categories: list[str]) -> str:
    """Short caller-id string CallKit can display in place of an unknown number."""
    cat = next((c for c in categories if c not in ("prior_offender",)), None)
    pretty = {
        "irs_scam": "Likely IRS scam", "scam": "Likely scam", "fraud": "Likely fraud",
        "robocall": "Robocall", "telemarketer": "Telemarketer", "spam": "Spam likely",
        "tech_support": "Tech-support scam", "phishing": "Phishing call",
    }
    if cat and cat in pretty:
        return pretty[cat]
    return {"fraud": "Likely fraud", "spam": "Spam likely"}.get(verdict, "Suspicious caller")


def _content_verdict(event: CallEvent) -> dict | None:
    """Run the VishGuard model on the transcript (deep path). None if no transcript."""
    if not event.transcript:
        return None
    try:
        from common.streaming.channel_pipeline import process_one
        v = process_one("vishing", {
            "caller_id": event.caller_id,
            "transcript": event.transcript,
        })
        return {
            "is_threat": bool(v.is_threat),
            "risk": float(v.risk_score),
            "confidence": float(v.classifier_conf),
            "anomaly_level": v.anomaly_level,
            "reasons": list(v.reasons)[:5],
            "action": getattr(v.action, "value", str(v.action)),
        }
    except Exception as e:
        logger.error("vish content path failed: %s", e)
        return None


def screen_call(event: CallEvent | dict) -> ScreenResult:
    """Screen a CallKit event through both paths and return a fused verdict."""
    if isinstance(event, dict):
        event = CallEvent.from_dict(event)

    paths: list[str] = []
    reasons: list[str] = []

    # --- reputation path (always) ---
    rep = score_number(event.caller_id)
    rep_dict = rep.to_dict()
    rep_risk = rep.risk
    if rep.sources:
        paths.append("reputation")
        if rep.risk >= _LABEL_AT:
            src = ", ".join(rep.sources)
            cat = (rep.categories or ["spam"])[0].replace("_", " ")
            n = f" by {rep.report_count} reports" if rep.report_count else ""
            reasons.append(f"Number flagged as {cat}{n} (sources: {src}).")
    elif rep.raw.get("provider_error"):
        paths.append("reputation")
        reasons.append(f"Provider error (ipqs): {rep.raw['provider_error']}")

    # --- transcription path (deep, optional) ---
    content = _content_verdict(event)
    content_risk = 0.0
    if content is not None:
        paths.append("transcription")
        content_risk = content["risk"]
        if content["is_threat"]:
            for r in content["reasons"][:3]:
                reasons.append(r)

    # --- voice spoof path (voicemail file only; never solo-BLOCK) ---
    voice_risk = 0.0
    voice = None
    try:
        from VishGuard.vish_mlm.voice_spoof import score_event_audio
        voice = score_event_audio(event.raw)
    except Exception as e:
        logger.debug("voice spoof path skipped: %s", e)
        voice = None
    if voice and voice.get("ok"):
        paths.append("voice")
        voice_risk = float(voice.get("risk") or 0.0)
        # Cap: voice alone may lift into LABEL/SILENCE band, not BLOCK.
        voice_risk = min(voice_risk, _SILENCE_AT + 0.05)
        for code in voice.get("codes") or []:
            if code == "SYNTHETIC_VOICE_SUSPECTED":
                reasons.append("Voicemail audio looks synthetic (cloned / TTS cues).")
            elif code == "VOICE_SILENCE_PAD":
                reasons.append("Voicemail is mostly silence — possible pad/evasion.")
            elif code == "VOICE_FLAT_SPECTRUM":
                reasons.append("Voicemail spectrum is unusually flat for a phone recording.")

    # --- fuse ---
    risk = max(rep_risk, content_risk, voice_risk)
    # agreement bump: both independent paths see danger → more certain
    if rep_risk >= _LABEL_AT and content_risk >= _LABEL_AT:
        risk = min(1.0, risk + 0.08)
    if voice_risk >= _LABEL_AT and (rep_risk >= _LABEL_AT or content_risk >= _LABEL_AT):
        risk = min(1.0, risk + 0.05)
    # trust adjustments
    if event.carrier_verified is True:        # STIR/SHAKEN attested → slightly trust
        risk = max(0.0, risk - 0.05)
    if event.carrier_verified is False:       # spoof-likely → slightly distrust
        risk = min(1.0, risk + 0.05)

    verdict = rep.verdict.value if rep.verdict != Verdict.UNKNOWN else (
        "fraud" if risk >= _BLOCK_AT else "spam" if risk >= _LABEL_AT else "unknown")
    action = _action_for(risk, contact_known=event.contact_known)
    is_threat = action in (CallKitAction.BLOCK, CallKitAction.SILENCE)

    if not reasons:
        reasons.append("No reputation hits and no transcript to analyze — "
                       "caller is unknown but not flagged." if not paths
                       else "Caller is known to feeds but below the risk threshold.")
    if event.contact_known and action != CallKitAction.BLOCK:
        reasons.append("Number is in your contacts — not blocked.")

    label = _label_for(verdict, rep.categories) if is_threat or action == CallKitAction.LABEL else ""
    if voice and voice.get("ok") and "SYNTHETIC_VOICE_SUSPECTED" in (voice.get("codes") or []):
        if not label:
            label = "Possible cloned voice"

    return ScreenResult(
        action=action, is_threat=is_threat, risk=risk, verdict=verdict, label=label,
        reputation=rep_dict, content=content, reasons=reasons[:6], paths=paths,
    )
