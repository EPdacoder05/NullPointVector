"""
CI regression gate: the live model MUST clear the golden held-out thresholds.

This is what makes the resume's accuracy claim enforceable — if a change drops
accuracy below 90%, pushes FPR above 10%, or lets a pump-fake through, CI fails.
"""
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
# Repo root first so `common.*` imports inside phish eval resolve in CI.
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "PhishGuard" / "phish_mlm"))


def test_golden_gate_passes():
    from eval.evaluate import evaluate, passes_gate
    from phishing_detector import detector

    m = evaluate(detector)
    assert m["accuracy"] >= 0.90, f"accuracy {m['accuracy']:.3f} < 0.90"
    assert m["fpr"] <= 0.10, f"fpr {m['fpr']:.3f} > 0.10"
    assert m["pump_fake_recall"] >= 1.0, "a pump-fake phish got through"
    assert passes_gate(m)


def test_pumpfake_same_text_opposite_auth():
    """Identical 'was this you?' text → SAFE on aligned auth, PHISH on failing auth."""
    from phishing_detector import detector

    phrase = ("New sign-in to your account from iPhone. Was this you? "
              "If not, secure your account.")
    aligned = {"subject": "alert", "body": phrase, "from": "no-reply@google.com",
               "headers": {"authentication_results":
                           "mx; spf=pass smtp.mailfrom=google.com; "
                           "dkim=pass header.d=google.com; dmarc=pass header.from=google.com",
                           "return_path": "<bounce@google.com>"}}
    spoof = {"subject": "alert", "body": phrase, "from": "no-reply@google.com",
             "headers": {"authentication_results":
                         "mx; spf=fail smtp.mailfrom=evil.ru; "
                         "dkim=fail header.d=evil.ru; dmarc=fail header.from=google.com",
                         "return_path": "<bounce@evil.ru>"}}
    assert detector.predict(aligned)[0] == 0
    assert detector.predict(spoof)[0] == 1
