"""
Self-learning / anti-drift training subsystem for PhishGuard.

Modules:
    registry        — versioned model artifacts, champion pointer, rollback
    feedback_buffer — durable append-only store of user/triage feedback
    drift           — PSI feature drift + prediction-confidence drift
    trainer         — champion/challenger retraining with golden-gate promotion

Design goals (mirrors System-Design-Engineering-Universal-Reference/ml):
    - No catastrophic forgetting: every retrain replays the full seed set.
    - No poisoning: a candidate is promoted ONLY if it clears the golden gate
      AND does not regress versus the current champion.
    - Full auditability: every candidate is versioned with metrics + data hash.
    - Cheap rollback: champion pointer is a single atomic file write.

Imports are LAZY (PEP 562 module __getattr__) so importing one submodule (e.g.
feedback_buffer from the detector) does not drag in the heavier trainer/eval
import chain.
"""
__all__ = ["ModelRegistry", "FeedbackBuffer", "DriftMonitor", "psi",
           "Trainer", "TrainResult"]


def __getattr__(name):
    if name == "ModelRegistry":
        from .registry import ModelRegistry
        return ModelRegistry
    if name == "FeedbackBuffer":
        from .feedback_buffer import FeedbackBuffer
        return FeedbackBuffer
    if name in ("DriftMonitor", "psi"):
        from . import drift
        return getattr(drift, name)
    if name in ("Trainer", "TrainResult"):
        from . import trainer
        return getattr(trainer, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
