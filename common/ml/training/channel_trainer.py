"""
Generalized champion/challenger trainer for the SMS/voice channels.

Mirrors PhishGuard's Trainer discipline (anti-poisoning, gated promotion) but for
any ``ChannelDetector`` (SmishGuard, VishGuard):

    1. Assemble training data = seed corpus (always replayed)
                              + durable feedback buffer (reservoir-capped)
                              + labeled threats from the vector DB (this channel)
                              + (optional) external-feed seed connector rows
    2. Train a CANDIDATE artifact from scratch (full refit → no forgetting) + calibrate.
    3. Evaluate the candidate on the HELD-OUT golden set (with CIs).
    4. Promote ONLY if it clears the gate AND does not regress vs the champion.
    5. Version every candidate in the per-channel registry (auditable, rollbackable).

A single bad feedback label can never silently degrade production — it must clear
the golden gate first.
"""
from __future__ import annotations

import hashlib
import logging
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from common.ml.channel_detector import build_artifact, predict_with
from common.ml.training.channel_eval import evaluate, passes_gate, load_golden
from common.ml.training.gate_decide import decide_promotion

logger = logging.getLogger(__name__)

_MAX_FEEDBACK = 20_000

# Per-channel golden file (held-out, never used for training).
_GOLDEN = {
    "smishing": "SmishGuard/smish_mlm/eval/golden_smish.jsonl",
    "vishing": "VishGuard/vish_mlm/eval/golden_vish.jsonl",
}
_REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass
class TrainResult:
    channel: str
    version: str
    promoted: bool
    reason: str
    n_train: int
    candidate_metrics: Dict = field(default_factory=dict)
    champion_metrics: Dict = field(default_factory=dict)


class _ArtifactScorer:
    """Wrap a candidate artifact as a ``.predict(record)`` for evaluate()."""
    def __init__(self, artifact: dict, text_fn, numeric_fn, threshold: float):
        self._a = artifact
        self._text_fn = text_fn
        self._numeric_fn = numeric_fn
        self._threshold = threshold

    def predict(self, record: dict) -> Tuple[int, float]:
        return predict_with(self._a, self._text_fn(record), record,
                            self._numeric_fn, self._threshold)


class ChannelTrainer:
    def __init__(self, channel: str, registry=None, feedback=None):
        if channel not in _GOLDEN:
            raise ValueError(f"no golden set configured for channel: {channel}")
        self.channel = channel

        from common.streaming.channel_pipeline import get_detector
        self.detector = get_detector(channel)

        models_dir = self.detector.model_path.parent
        from PhishGuard.phish_mlm.training.registry import ModelRegistry
        from PhishGuard.phish_mlm.training.feedback_buffer import FeedbackBuffer
        self.registry = registry or ModelRegistry(models_dir)
        self.feedback = feedback or FeedbackBuffer(models_dir / "feedback.jsonl")
        self.golden_path = _REPO_ROOT / _GOLDEN[channel]

    # ------------------------------------------------------------- data prep
    def _assemble_training_data(self) -> Tuple[List[str], List[int], List[dict]]:
        texts: List[str] = []
        labels: List[int] = []
        metas: List[dict] = []

        # 1) seed corpus (always replayed → no catastrophic forgetting)
        for rec, lbl in self.detector.seed_fn():
            t = self.detector.text_fn(rec)
            if t:
                texts.append(t); labels.append(int(lbl)); metas.append(rec)

        # 2) durable feedback (reservoir-capped)
        for row in self.feedback.reservoir_sample(_MAX_FEEDBACK, seed=42):
            rec = row.get("record") or row.get("email") or {}
            t = self.detector.text_fn(rec)
            if t:
                texts.append(t); labels.append(int(row.get("label", 0))); metas.append(rec)

        # 3) labeled threats from the vector DB for THIS channel
        for rec, lbl in self._labeled_threats_from_db():
            t = self.detector.text_fn(rec)
            if t:
                texts.append(t); labels.append(lbl); metas.append(rec)

        # 4) external-feed seed connector rows (offline-safe; empty if unconfigured)
        for rec, lbl in self._external_seed_rows():
            t = self.detector.text_fn(rec)
            if t:
                texts.append(t); labels.append(int(lbl)); metas.append(rec)

        return texts, labels, metas

    def _labeled_threats_from_db(self) -> List[Tuple[dict, int]]:
        try:
            from Autobot.VectorDB.NullPoint_Vector import get_all_threats
            rows = get_all_threats(threat_type=self.channel, limit=5_000) or []
        except Exception as e:
            logger.info("ChannelTrainer[%s]: DB threats unavailable (%s); skipping.",
                        self.channel, e)
            return []
        out: List[Tuple[dict, int]] = []
        for r in rows:
            meta = r.get("metadata", {}) or {}
            label = meta.get("label", 1 if r.get("is_threat") else None)
            if label is None:
                continue
            content = r.get("content") or meta.get("content") or ""
            if not content:
                continue
            sender = r.get("sender", "")
            out.append(({"body": content, "transcript": content,
                         "from": sender, "caller_id": sender}, int(label)))
        return out

    def _external_seed_rows(self) -> List[Tuple[dict, int]]:
        """Rows contributed by external-feed connectors (R3 seed expansion).

        Fail-safe + offline-safe: returns [] when no connector is configured, so a
        retrain never depends on a third-party API being reachable.
        """
        try:
            from common.ml.training.seed_connectors import collect_channel_seed
            return collect_channel_seed(self.channel)
        except Exception as e:
            logger.info("ChannelTrainer[%s]: no external seed rows (%s).", self.channel, e)
            return []

    @staticmethod
    def _data_hash(texts: List[str], labels: List[int]) -> str:
        h = hashlib.sha256()
        for t, l in zip(texts, labels):
            h.update(str(l).encode()); h.update(t.encode("utf-8", "ignore"))
        return h.hexdigest()[:16]

    # ------------------------------------------------------------------- run
    def run(self, force_promote: bool = False, dry_run: bool = False) -> TrainResult:
        """Train + evaluate + (optionally) promote a candidate.

        dry_run=True evaluates and reports the gate decision WITHOUT writing a
        registry version, persisting the champion, or hot-swapping — useful to
        check "would this promote?" without mutating committed artifacts.
        """
        texts, labels, metas = self._assemble_training_data()
        n = len(texts)
        if len(set(labels)) < 2:
            return TrainResult(self.channel, "", False, "need both classes to train", n)

        logger.info("ChannelTrainer[%s]: training candidate on %d samples…", self.channel, n)
        candidate = build_artifact(texts, labels, metas, self.detector.numeric_fn,
                                   self.detector.num_features, calibrate=True)

        golden_rows = load_golden(self.golden_path)
        cand_scorer = _ArtifactScorer(candidate, self.detector.text_fn,
                                      self.detector.numeric_fn, self.detector.threshold)
        cand_metrics = evaluate(cand_scorer, golden_rows)
        champ_metrics = self._champion_metrics(golden_rows)

        promoted, reason = self._decide(cand_metrics, champ_metrics, force_promote)

        if dry_run:
            return TrainResult(self.channel, "(dry-run)", promoted,
                               f"[dry-run] {reason}", n,
                               _slim(cand_metrics), _slim(champ_metrics))

        version = self.registry.save_candidate(
            candidate, _slim(cand_metrics),
            extra_meta={"channel": self.channel, "n_train": n,
                        "data_hash": self._data_hash(texts, labels),
                        "feature_version": self.detector.num_features,
                        "promoted": promoted})

        if promoted:
            self.registry.promote(version)
            self._persist_champion(candidate)
            self.detector.load_artifact(candidate)   # hot-swap running process
            self.feedback.archive()
            logger.info("ChannelTrainer[%s]: PROMOTED %s — %s", self.channel, version, reason)
        else:
            logger.info("ChannelTrainer[%s]: kept champion — %s (%s archived)",
                        self.channel, reason, version)

        return TrainResult(self.channel, version, promoted, reason, n,
                           _slim(cand_metrics), _slim(champ_metrics))

    # ------------------------------------------------------------- internals
    def _champion_metrics(self, golden_rows: List[dict]) -> Dict:
        champ = self.registry.load_champion()
        if champ is not None:
            artifact, _meta = champ
            scorer = _ArtifactScorer(artifact, self.detector.text_fn,
                                     self.detector.numeric_fn, self.detector.threshold)
            return evaluate(scorer, golden_rows)
        return evaluate(self.detector, golden_rows)  # benchmark the live model

    @staticmethod
    def _decide(cand: Dict, champ: Dict, force: bool) -> Tuple[bool, str]:
        return decide_promotion(
            cand, champ, force,
            gate_ok=passes_gate(cand),
            gate_fail_reason=(
                f"candidate failed gate (recall={cand['recall']:.3f}, "
                f"fpr={cand['fpr']:.3f}, acc={cand['accuracy']:.3f})"
            ),
            primary_key="recall",
        )

    def _persist_champion(self, artifact: dict) -> None:
        with open(self.detector.model_path, "wb") as f:
            pickle.dump(artifact, f)


def _slim(metrics: Dict) -> Dict:
    return {k: v for k, v in metrics.items() if k != "failures"}


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    ch = sys.argv[1] if len(sys.argv) > 1 else "smishing"
    res = ChannelTrainer(ch).run()
    print(f"\n[{res.channel}] version={res.version} promoted={res.promoted}")
    print(f"reason: {res.reason}")
    cm = res.candidate_metrics
    print(f"candidate: recall={cm.get('recall'):.3f} fpr={cm.get('fpr'):.3f} "
          f"acc={cm.get('accuracy'):.3f} n={cm.get('n')}")
