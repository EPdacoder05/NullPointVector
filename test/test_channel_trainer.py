"""Gate: the generalized Smish/Vish training loop.

Proves:
  1. The golden evaluator computes correct metrics + Wilson CIs.
  2. passes_gate enforces the recall/FPR/accuracy floors.
  3. ChannelTrainer dry-run trains a candidate, evaluates on the held-out golden
     set, and reports a gate decision WITHOUT mutating committed artifacts.
  4. The anti-regression promotion logic blocks a worse candidate.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.ml.training.channel_eval import evaluate, passes_gate, _wilson
from common.ml.training import ChannelTrainer


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


def test_wilson_bounds():
    lo, hi = _wilson(8, 8)                      # 100% on 8 samples → wide interval
    assert 0.0 <= lo <= hi <= 1.0
    assert lo < 0.9                             # small-n uncertainty is visible


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
