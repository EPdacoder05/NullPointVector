"""
Anti-poisoning test: a champion/challenger candidate trained on POISONED
feedback must NOT be promoted.

This proves the core anti-drift guarantee — a flood of mislabeled feedback
(legit marked phish, phish marked safe) degrades the candidate on the golden
set, so the gate keeps the existing champion and the bad model is only archived.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "PhishGuard" / "phish_mlm"))


def test_poisoned_candidate_is_rejected():
    from PhishGuard.phish_mlm.training.trainer import Trainer
    from PhishGuard.phish_mlm.training.registry import ModelRegistry
    from PhishGuard.phish_mlm.training.feedback_buffer import FeedbackBuffer

    tmp = Path(tempfile.mkdtemp())
    registry = ModelRegistry(tmp)              # fresh → champion = live good model
    feedback = FeedbackBuffer(tmp / "poison.jsonl")

    # Poison: many legit emails labeled phish AND phish labeled safe.
    legit_texts = [
        "Meeting at 2pm in conference room B, agenda attached",
        "Your order has shipped and arrives Tuesday",
        "Thanks for the report, looks great, ship it",
        "Reminder: submit your timesheet by Friday",
        "Lunch Friday? trying the new ramen spot",
    ]
    phish_texts = [
        "URGENT verify your account at paypal-secure.ru now or be suspended",
        "You won $1,000,000 claim at winner-claim.tk today",
        "Your mailbox is full re-validate password at webmail-quota.click",
    ]
    for _ in range(30):
        for t in legit_texts:
            feedback.append({"subject": "", "body": t, "from": "a@corp.com"}, label=1)
        for t in phish_texts:
            feedback.append({"subject": "", "body": t, "from": "x@paypal-secure.ru"}, label=0)

    result = Trainer(registry=registry, feedback=feedback).run()

    assert not result.promoted, (
        f"poisoned candidate was promoted! reason={result.reason} "
        f"metrics={result.candidate_metrics}"
    )
    assert "regression" in result.reason or "failed gate" in result.reason


if __name__ == "__main__":
    test_poisoned_candidate_is_rejected()
    print("anti-poisoning gate held ✅")
