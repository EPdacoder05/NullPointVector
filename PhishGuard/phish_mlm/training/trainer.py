"""
Champion/challenger trainer with golden-gate promotion.

PIPELINE (one run):
    1. Assemble training data = seed corpus (always replayed)
                              + durable feedback buffer
                              + labeled threats from the vector DB (if reachable)
    2. Train a CANDIDATE artifact from scratch (full refit → no forgetting),
       with probability calibration.
    3. Evaluate the candidate on the HELD-OUT golden set.
    4. Compare against the current CHAMPION.
    5. Promote ONLY if the candidate (a) clears the golden gate AND
       (b) does not regress accuracy / FPR / pump-fake recall vs champion.
    6. Every candidate is versioned in the registry (auditable, rollback-able).
       On promotion the live detector is hot-swapped and the feedback buffer is
       archived.

This is the anti-poisoning, anti-drift safeguard: a single bad feedback label
can never silently degrade production — it must survive the gate first.
"""
import hashlib
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_PHISH_MLM_DIR = Path(__file__).resolve().parent.parent  # .../phish_mlm
if str(_PHISH_MLM_DIR) not in sys.path:
    sys.path.insert(0, str(_PHISH_MLM_DIR))

from phishing_detector import (  # noqa: E402
    detector as live_detector,
    build_artifact, predict_with, extract_email_text,
    MODEL_DIR, MODEL_PATH, NUM_STRUCTURAL_FEATURES, FEEDBACK_PATH,
)
from eval.evaluate import evaluate, passes_gate  # noqa: E402
from common.ml.training.gate_decide import decide_promotion  # noqa: E402

from .registry import ModelRegistry
from .feedback_buffer import FeedbackBuffer

FEEDBACK_PATH.parent.mkdir(parents=True, exist_ok=True)

# Hard cap on feedback samples folded into a single retrain (reservoir-sampled).
_MAX_FEEDBACK = 20_000


@dataclass
class TrainResult:
    version: str
    promoted: bool
    reason: str
    n_train: int
    candidate_metrics: Dict = field(default_factory=dict)
    champion_metrics: Dict = field(default_factory=dict)


class _ArtifactDetector:
    """Adapter exposing .predict(email) for an artifact dict (for evaluate())."""

    def __init__(self, artifact: dict):
        self._artifact = artifact

    def predict(self, email_data: dict) -> Tuple[int, float]:
        return predict_with(self._artifact, email_data)


class Trainer:
    def __init__(self,
                 registry: Optional[ModelRegistry] = None,
                 feedback: Optional[FeedbackBuffer] = None):
        self.registry = registry or ModelRegistry(MODEL_DIR)
        self.feedback = feedback or FeedbackBuffer(FEEDBACK_PATH)

    # ------------------------------------------------------------- data prep
    def _assemble_training_data(self) -> Tuple[List[str], List[int], List[dict]]:
        """seed corpus + feedback buffer + labeled DB threats → (texts, labels, metas)."""
        texts, labels, metas = live_detector._seed_corpus()
        texts, labels, metas = list(texts), list(labels), list(metas)

        # Durable feedback (reservoir-capped so the set can't grow unbounded).
        fb = self.feedback.reservoir_sample(_MAX_FEEDBACK, seed=42)
        for row in fb:
            email = row.get("email", {})
            t = extract_email_text(email)
            if t:
                texts.append(t)
                labels.append(int(row.get("label", 0)))
                metas.append(email)

        # Labeled threats from the vector DB (best-effort; skip if unreachable).
        for t, lbl, email in self._labeled_threats_from_db():
            texts.append(t)
            labels.append(lbl)
            metas.append(email)

        return texts, labels, metas

    @staticmethod
    def _labeled_threats_from_db() -> List[Tuple[str, int, dict]]:
        try:
            sys.path.insert(0, str(_PHISH_MLM_DIR.parent.parent))
            from Autobot.VectorDB.NullPoint_Vector import get_all_threats
            rows = get_all_threats(limit=5_000) or []
        except Exception as e:
            logger.info(f"Trainer: DB labeled threats unavailable ({e}); skipping.")
            return []
        out = []
        for r in rows:
            meta = r.get("metadata", {}) or {}
            label = meta.get("label")
            if label is None:
                # threats stored without an explicit label are assumed phish
                label = 1 if r.get("threat_type") else None
            if label is None:
                continue
            content = r.get("content") or r.get("preprocessed_text") or ""
            if not content:
                continue
            email = {"subject": "", "body": content, "from": r.get("sender", "")}
            out.append((content, int(label), email))
        return out

    @staticmethod
    def _data_hash(texts: List[str], labels: List[int]) -> str:
        h = hashlib.sha256()
        for t, l in zip(texts, labels):
            h.update(str(l).encode())
            h.update(t.encode("utf-8", "ignore"))
        return h.hexdigest()[:16]

    # ------------------------------------------------------------------- run
    def run(self, force_promote: bool = False) -> TrainResult:
        texts, labels, metas = self._assemble_training_data()
        n = len(texts)
        if len(set(labels)) < 2:
            return TrainResult("", False, "need both classes to train", n)

        logger.info(f"Trainer: training candidate on {n} samples "
                    f"(seed + feedback + db)…")
        candidate = build_artifact(texts, labels, metas, calibrate=True)
        cand_metrics = evaluate(_ArtifactDetector(candidate))

        champ_metrics = self._champion_metrics()

        promoted, reason = self._decide(cand_metrics, champ_metrics, force_promote)

        version = self.registry.save_candidate(
            candidate, cand_metrics,
            extra_meta={
                "n_train": n,
                "data_hash": self._data_hash(texts, labels),
                "feature_version": NUM_STRUCTURAL_FEATURES,
                "promoted": promoted,
            },
        )

        if promoted:
            self.registry.promote(version)
            self._persist_champion(candidate)
            live_detector.load_artifact(candidate)  # hot-swap running process
            self.feedback.archive()
            logger.info(f"Trainer: PROMOTED {version} — {reason}")
        else:
            logger.info(f"Trainer: kept champion — {reason} (candidate {version} archived)")

        return TrainResult(
            version=version, promoted=promoted, reason=reason, n_train=n,
            candidate_metrics=_slim(cand_metrics), champion_metrics=_slim(champ_metrics),
        )

    # ------------------------------------------------------------- internals
    def _champion_metrics(self) -> Dict:
        champ = self.registry.load_champion()
        if champ is not None:
            artifact, _meta = champ
            return evaluate(_ArtifactDetector(artifact))
        # No registry champion yet → benchmark the live (on-disk) model.
        return evaluate(live_detector)

    @staticmethod
    def _decide(cand: Dict, champ: Dict, force: bool) -> Tuple[bool, str]:
        return decide_promotion(
            cand, champ, force,
            gate_ok=passes_gate(cand),
            gate_fail_reason=(
                f"candidate failed gate "
                f"(acc={cand['accuracy']:.3f}, fpr={cand['fpr']:.3f}, "
                f"pump={cand['pump_fake_recall']:.2f})"
            ),
            primary_key="pump_fake_recall",
            primary_eps=0.0,  # historical: any pump_fake drop is regression
        )

    @staticmethod
    def _persist_champion(artifact: dict) -> None:
        """Write the promoted artifact to the path the detector singleton loads."""
        import pickle
        with open(MODEL_PATH, "wb") as f:
            pickle.dump({
                "word_tfidf": artifact["word_tfidf"],
                "char_tfidf": artifact["char_tfidf"],
                "clf": artifact["clf"],
                "platt": artifact.get("platt"),
                "feature_version": artifact.get("feature_version", NUM_STRUCTURAL_FEATURES),
            }, f)


def _slim(metrics: Dict) -> Dict:
    """Drop the verbose failure list for compact JSON responses/logs."""
    return {k: v for k, v in metrics.items() if k != "failures"}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    result = Trainer().run()
    print(f"\nversion={result.version} promoted={result.promoted}")
    print(f"reason: {result.reason}")
    print(f"candidate: acc={result.candidate_metrics.get('accuracy'):.3f} "
          f"fpr={result.candidate_metrics.get('fpr'):.3f} "
          f"pump={result.candidate_metrics.get('pump_fake_recall')}")
