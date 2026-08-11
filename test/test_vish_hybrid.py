"""R1 gate: the hybrid CallKit→VishGuard contract.

Proves the reputation framework + hybrid adapter behave correctly and FAIL-SAFE:
  1. Number normalization is stable (E.164 + alphanumeric sender ids).
  2. Reputation fusion: weighted-max + consensus boost, verdict mapping.
  3. With NO API keys configured, screening still works (degrades to local/none),
     never raises, and an unknown number is allowed.
  4. A known-fraud number (reputation hit) → BLOCK even with no transcript.
  5. A clean number + scam transcript (content path) → escalated action.
  6. A number in the user's contacts is never auto-blocked.

Runs fully offline: external providers are disabled (no keys) and the local DB
provider is monkeypatched, so there are no network or DB dependencies.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.reputation.base import (
    normalize_number, fuse, ReputationScore, Verdict,
)
from common.reputation.aggregator import ReputationAggregator
from common.reputation.providers import LocalThreatDBProvider
from common.vish import CallEvent, screen_call
from common.vish.contract import CallKitAction


# --------------------------------------------------------------- normalization
def test_normalize_number():
    assert normalize_number("(800) 555-1001") == "+18005551001"
    assert normalize_number("8005551001") == "+18005551001"
    assert normalize_number("+44 7700 900103") == "+447700900103"
    assert normalize_number("IRS") == "IRS"
    assert normalize_number("") == ""


# ------------------------------------------------------------------- fusion
def test_fuse_weighted_max_and_consensus():
    parts = [
        ReputationScore(number="+1", risk=0.6, categories=["robocall"], sources=["nomorobo"]),
        ReputationScore(number="+1", risk=0.9, categories=["irs_scam"], sources=["hiya"]),
    ]
    fused = fuse("+1", parts)
    assert fused.risk >= 0.9                      # weighted-max base
    assert fused.verdict == Verdict.FRAUD
    assert set(fused.sources) == {"nomorobo", "hiya"}
    assert fused.confidence > 0.4                 # multiple sources → higher confidence


def test_fuse_empty_is_unknown():
    fused = fuse("+1", [])
    assert fused.verdict == Verdict.UNKNOWN
    assert fused.risk == 0.0


# --------------------------------------------------- fail-safe with no providers
def test_unknown_number_allowed_no_keys(monkeypatch):
    # No external keys + local provider returns nothing → unknown → ALLOW.
    monkeypatch.setattr(LocalThreatDBProvider, "_lookup", lambda self, n: None)
    agg = ReputationAggregator()
    monkeypatch.setattr("common.reputation.aggregator.get_aggregator", lambda: agg)
    import common.vish.adapter as adapter
    monkeypatch.setattr(adapter, "score_number",
                        lambda n, use_cache=True: agg.score(n, use_cache=False))

    res = screen_call(CallEvent(caller_id="+18005559999"))
    assert res.action == CallKitAction.ALLOW
    assert res.is_threat is False
    assert "reputation" not in res.paths  # no source reported


# ---------------------------------------------------- reputation-only → block
def test_known_fraud_number_blocks(monkeypatch):
    hit = ReputationScore(number="+18005550301", risk=0.95, verdict=Verdict.FRAUD,
                          categories=["irs_scam"], sources=["local", "hiya"],
                          report_count=4, confidence=0.9)
    import common.vish.adapter as adapter
    monkeypatch.setattr(adapter, "score_number", lambda n, use_cache=True: hit)

    res = screen_call(CallEvent(caller_id="+18005550301"))
    assert res.action == CallKitAction.BLOCK
    assert res.is_threat is True
    assert res.verdict == "fraud"
    assert res.label  # a human label is set for CallKit to show
    assert "reputation" in res.paths


# --------------------------------------------- content path escalates clean number
def test_clean_number_scam_transcript_escalates(monkeypatch):
    clean = ReputationScore(number="+15551234567", risk=0.0, verdict=Verdict.UNKNOWN)
    import common.vish.adapter as adapter
    monkeypatch.setattr(adapter, "score_number", lambda n, use_cache=True: clean)

    event = CallEvent(
        caller_id="+15551234567",
        transcript=("This is the IRS. A warrant has been issued for your arrest over "
                    "unpaid taxes. Press 1 to settle immediately or face legal action."),
    )
    res = screen_call(event)
    assert "transcription" in res.paths
    # The VishGuard model should flag this scripted scam → at least a label.
    assert res.action in (CallKitAction.LABEL, CallKitAction.SILENCE, CallKitAction.BLOCK)


# ----------------------------------------------------- contacts are protected
def test_known_contact_not_blocked(monkeypatch):
    hit = ReputationScore(number="+15551112222", risk=0.95, verdict=Verdict.FRAUD,
                          categories=["spam"], sources=["hiya"], confidence=0.9)
    import common.vish.adapter as adapter
    monkeypatch.setattr(adapter, "score_number", lambda n, use_cache=True: hit)

    res = screen_call(CallEvent(caller_id="+15551112222", contact_known=True))
    assert res.action != CallKitAction.BLOCK
    assert res.action != CallKitAction.SILENCE


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call(["python", "-m", "pytest", "-q", __file__]))
