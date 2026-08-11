"""
Generalized training loops for the channel detectors (Smish/Vish).

PhishGuard already has a champion/challenger trainer; these modules bring the same
gated-promotion discipline to the SMS/voice channels via the shared
`ChannelDetector`, so all three guards retrain, evaluate, and promote identically.

    from common.ml.training import ChannelTrainer
    ChannelTrainer("smishing").run()
"""
from common.ml.training.channel_trainer import ChannelTrainer, TrainResult
from common.ml.training.channel_eval import evaluate, passes_gate, load_golden

__all__ = ["ChannelTrainer", "TrainResult", "evaluate", "passes_gate", "load_golden"]
