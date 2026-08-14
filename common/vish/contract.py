"""
The CallKit → VishGuard data contract (R1).

This is the single source of truth for what the iOS client sends and what the
backend returns. It is intentionally small and stable so the Swift/CallKit side
can be built against it independently of model internals.

WHY A CONTRACT (the R1 decision):
    CallKit surfaces a *call event + caller ID*, never an audio transcript. The
    VishGuard model scores *text*. We chose the **hybrid** path:

      • PRE-RING data plane       → compile known NUMBER reputation into Call
                                     Directory, or serve it through Apple's
                                     separately provisioned Live Caller ID path.
      • DEEP path (voicemail/opt-in)→ transcribe (Apple Speech / Whisper) and
                                     score the TRANSCRIPT with VishGuard for a
                                     content-level verdict + explainability.

    The two can be fused into one `ScreenResult` policy recommendation. The
    current iOS app does not receive native carrier-call events and does not call
    this endpoint automatically at ring time. A backend response also cannot
    directly silence an arbitrary carrier call; iOS applies only capabilities
    exposed by the installed Apple extension.

INPUT  (CallEvent)  — submitted by an authorized explicit/owned transport path:
    {
      "caller_id": "+18005551001",     # required; E.164 or alphanumeric sender id
      "phase": "incoming",             # incoming | voicemail | post_call
      "transcript": null,              # optional; present → deep text path
      "direction": "inbound",          # inbound | outbound
      "contact_known": false,          # is the number in the user's contacts?
      "carrier_verified": null,        # STIR/SHAKEN attest result if available
      "timestamp": "2026-06-30T19:00:00Z",
      "device_id": "opaque-per-install",
      "raw": { "audio_path": null }    # optional wav → voice spoof path (never solo-BLOCK)
    }

OUTPUT (ScreenResult):
    {
      "action": "block",               # allow | label | silence | block
      "is_threat": true,
      "risk": 0.93,
      "verdict": "fraud",
      "label": "Likely IRS scam",      # short string CallKit shows as caller name
      "reputation": { ...ReputationScore.to_dict()... },
      "content": { ...VishGuard verdict (only if transcript was scored)... },
      "reasons": ["Reported by 3 feeds as IRS scam", "Pressure/urgency language"],
      "paths": ["reputation", "transcription", "voice"]
    }
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class CallPhase(str, Enum):
    INCOMING = "incoming"      # phone is ringing — live screening, no transcript yet
    VOICEMAIL = "voicemail"    # caller left VM — transcript available for deep path
    POST_CALL = "post_call"    # call ended — optional recorded-transcript analysis


class CallKitAction(str, Enum):
    """Channel-neutral policy recommendation, not proof of an iOS capability."""
    ALLOW = "allow"        # ring normally
    LABEL = "label"        # ring, but show a caller-id warning label
    SILENCE = "silence"    # send to voicemail silently (suspicious, not certain)
    BLOCK = "block"        # block outright (high-confidence fraud)


@dataclass
class CallEvent:
    """Normalized CallKit event (see module docstring for the wire format)."""
    caller_id: str
    phase: CallPhase = CallPhase.INCOMING
    transcript: Optional[str] = None
    direction: str = "inbound"
    contact_known: bool = False
    carrier_verified: Optional[bool] = None   # STIR/SHAKEN attestation, if known
    timestamp: Optional[str] = None
    device_id: Optional[str] = None
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "CallEvent":
        phase = d.get("phase", "incoming")
        try:
            phase = CallPhase(phase)
        except ValueError:
            phase = CallPhase.INCOMING
        return cls(
            caller_id=str(d.get("caller_id") or d.get("from") or d.get("number") or "").strip(),
            phase=phase,
            transcript=d.get("transcript") or d.get("voicemail_text") or None,
            direction=d.get("direction", "inbound"),
            contact_known=bool(d.get("contact_known", False)),
            carrier_verified=d.get("carrier_verified"),
            timestamp=d.get("timestamp"),
            device_id=d.get("device_id"),
            raw=d.get("raw") or {},
        )


@dataclass
class ScreenResult:
    action: CallKitAction
    is_threat: bool
    risk: float
    verdict: str
    label: str
    reputation: dict = field(default_factory=dict)
    content: Optional[dict] = None
    reasons: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "is_threat": self.is_threat,
            "risk": round(self.risk, 4),
            "verdict": self.verdict,
            "label": self.label,
            "reputation": self.reputation,
            "content": self.content,
            "reasons": self.reasons,
            "paths": self.paths,
        }
