"""Gate: the generalized Smish/Vish training loop.

Proves:
  1. The golden evaluator computes correct metrics + Wilson CIs.
  2. passes_gate enforces the recall/FPR/accuracy floors.
  3. ChannelTrainer dry-run trains a candidate, evaluates on the held-out golden
     set, and reports a gate decision WITHOUT mutating committed artifacts.
  4. The anti-regression promotion logic blocks a worse candidate.
"""
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.ml.channel_detector import ChannelDetector, verify_model_artifact
from common.ml.training.channel_eval import (
    evaluate,
    has_release_evidence,
    passes_gate,
    _wilson,
)
from common.ml.training import ChannelTrainer
from common.ml.training.gate_decide import decide_promotion
from common.grading import trusted_db_label, trusted_feedback_label


class _FakeDetector:
    """Predicts 1 iff the record body contains 'scam'."""
    def predict(self, rec):
        return (1 if "scam" in rec.get("body", "").lower() else 0, 0.9)


def test_evaluate_and_ci():
    rows = [
        {"label": 1, "body": "this is a scam call"},
        {"label": 1, "body": "scam scam scam"},
        {"label": 0, "body": "hi mom see you soon"},
        {"label": 0, "body": "your package arrived"},
    ]
    m = evaluate(_FakeDetector(), rows)
    assert m["n"] == 4
    assert m["recall"] == 1.0 and m["fpr"] == 0.0 and m["accuracy"] == 1.0
    assert len(m["recall_ci95"]) == 2 and m["recall_ci95"][0] <= 1.0


def test_passes_gate():
    good = {"recall": 0.96, "fpr": 0.02, "accuracy": 0.97}
    weak = {"recall": 0.80, "fpr": 0.02, "accuracy": 0.97}
    noisy = {"recall": 0.96, "fpr": 0.20, "accuracy": 0.97}
    assert passes_gate(good) is True
    assert passes_gate(weak) is False          # recall floor
    assert passes_gate(noisy) is False         # fpr ceiling


def test_predict_exception_invalidates_eval_and_is_not_a_true_negative():
    class BrokenDetector:
        def predict(self, _rec):
            raise RuntimeError("boom")

    m = evaluate(BrokenDetector(), [{"label": 0, "body": "ordinary message"}])
    assert m["evaluation_valid"] is False
    assert m["inference_errors"] == 1
    assert m["confusion"] == {"tp": 0, "tn": 0, "fp": 1, "fn": 0}
    assert passes_gate(m) is False


def test_small_perfect_set_is_not_release_evidence():
    rows = ([{"label": 1, "body": "scam"}] * 8
            + [{"label": 0, "body": "ordinary"}] * 8)
    m = evaluate(_FakeDetector(), rows)
    assert passes_gate(m) is True
    assert has_release_evidence(m) is False


def test_vish_point_875_recall_fails_shared_gate():
    metrics = {"recall": 0.875, "fpr": 0.0, "accuracy": 0.9375}
    assert passes_gate(metrics) is False


def test_cached_vish_metrics_are_reassessed_with_current_gate():
    from ui.kpi import reassess_channel_metrics

    metrics = {
        "available": True,
        "accuracy": 0.9375,
        "precision": 1.0,
        "recall": 0.875,
        "fpr": 0.0,
        "confusion": {"tp": 7, "tn": 8, "fp": 0, "fn": 1},
    }
    result = reassess_channel_metrics("vishing", metrics)
    assert result["gate_pass"] is False
    assert result["evidence_sufficient"] is False
    assert result["release_ready"] is False


def test_empty_latency_renders_as_not_measured():
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(str(Path("web/templates"))))
    template = env.get_template("benchmarks.html")
    unavailable = {"available": False, "reason": "test"}
    html = template.render(
        active="benchmarks",
        channels={},
        user=None,
        tz="UTC",
        tz_abbrev="UTC",
        tz_choices=[],
        hour12=False,
        quality={
            "phishing": unavailable,
            "smishing": unavailable,
            "vishing": unavailable,
        },
        latency={},
        max_lat_ms=1,
        snapshot_stale=False,
        snapshot_generated_at=None,
        ops=None,
        assist=[],
    )
    assert "Not measured in this snapshot" in html
    assert 'aria-label="Latency p50 p95"' not in html


def test_force_cannot_bypass_a_failed_safety_gate():
    promoted, reason = decide_promotion(
        {"recall": 0.0, "fpr": 1.0, "accuracy": 0.0},
        {},
        True,
        gate_ok=False,
        gate_fail_reason="failed safety gate",
        primary_key="recall",
    )
    assert promoted is False
    assert reason == "failed safety gate"


def test_db_training_requires_verified_label_provenance():
    assert trusted_db_label({
        "is_threat": True,
        "metadata": {"label": 1, "label_source": "model_prediction"},
    }) is None
    assert trusted_db_label({
        "is_threat": True,
        "metadata": {"label": 1},
    }) is None
    assert trusted_db_label({
        "label": 0,
        "metadata": {"label_source": "human_grade"},
    }) == 0


def test_feedback_training_requires_authenticated_source_and_explicit_label():
    assert trusted_feedback_label({"label": 1, "source": "model"}) is None
    assert trusted_feedback_label({"label": 1, "source": "user"}) is None
    assert trusted_feedback_label({"source": "console-grade"}) is None
    assert trusted_feedback_label({"label": 1, "source": "console-grade"}) == 1


def test_phishing_grade_buffers_once(monkeypatch, tmp_path):
    import common.grading as grading
    import common.ml.nudge as nudge

    class FakeDetector:
        clf = None

        def __init__(self):
            self.calls = []

        def learn_from_feedback(
            self, record, is_threat, *, buffer_feedback=True,
        ):
            self.calls.append((record, is_threat, buffer_feedback))

    fake = FakeDetector()
    monkeypatch.setenv("ENABLE_EPHEMERAL_NUDGE", "true")
    monkeypatch.setenv("ENV", "development")
    target = tmp_path / "feedback.jsonl"
    monkeypatch.setitem(grading._BUFFER_PATHS, "phishing", target)
    monkeypatch.setattr(nudge, "_get_detector", lambda _channel: fake)

    out = grading.record_grade(
        "phishing", {"body": "verified example"}, "block", nudge=True,
    )

    assert out["buffered"] is True
    assert target.read_text(encoding="utf-8").count("\n") == 1
    assert len(fake.calls) == 1
    assert fake.calls[0][2] is False


def test_wilson_bounds():
    lo, hi = _wilson(8, 8)                      # 100% on 8 samples → wide interval
    assert 0.0 <= lo <= hi <= 1.0
    assert lo < 0.9                             # small-n uncertainty is visible


def test_model_artifact_digest_is_checked_before_unpickle(monkeypatch, tmp_path):
    artifact = tmp_path / "candidate.pkl"
    artifact.write_bytes(b"not actually a pickle")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    monkeypatch.setenv("TEST_MODEL_SHA256", digest)
    verify_model_artifact(artifact, "TEST_MODEL_SHA256")

    artifact.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="digest verification failed"):
        verify_model_artifact(artifact, "TEST_MODEL_SHA256")


def test_production_never_cold_starts_when_model_is_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("ENV", "production")
    missing = tmp_path / "missing.pkl"

    with pytest.raises(RuntimeError, match="required in production"):
        ChannelDetector(
            name="TestGuard",
            model_path=missing,
            text_fn=lambda record: record.get("body", ""),
            numeric_fn=lambda _text, _record: [0.0],
            num_features=1,
            seed_fn=lambda: [({"body": "safe"}, 0), ({"body": "bad"}, 1)],
            artifact_digest_env="TEST_MODEL_SHA256",
        )

    assert not missing.exists()


def test_channel_trainer_dry_run_does_not_mutate():
    mp = Path(ChannelTrainer("smishing").detector.model_path)
    before = mp.read_bytes() if mp.exists() else None
    res = ChannelTrainer("smishing").run(dry_run=True)
    assert res.version == "(dry-run)"
    assert res.n_train > 0
    assert "recall" in res.candidate_metrics
    after = mp.read_bytes() if mp.exists() else None
    assert before == after, "dry-run must not rewrite the champion artifact"


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call(["python", "-m", "pytest", "-q", __file__]))
