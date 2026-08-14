"""
Channel-agnostic embedding-space anomaly detector (novel-attack surfacing).

This optional research layer fits an IsolationForest over MiniLM embeddings of
NORMAL messages for one channel.  Its output is only a novelty signal for
human triage; novelty is not evidence that a message is malicious.

WHY PER-CHANNEL:
    Email, SMS, and voice occupy different regions of embedding space (length,
    register, vocabulary). A single email-fit manifold flags ALL SMS/voice as
    "novel" (false alarms). A manifold fit on each channel's own benign traffic
    gives a calibrated novelty signal for that channel.

The fit corpus is capped by ``_MAX_FIT_SAMPLES``.  Scoring traverses every tree
and also runs an embedding model, so latency is hardware/model dependent and
must be measured on the deployment target.  This module makes no real-time or
constant-time latency claim.
"""
from __future__ import annotations

import logging
import pickle
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# Cap embeddings used for the initial fit (keeps cold-start fast; IF is robust).
_MAX_FIT_SAMPLES = 4000


class AnomalyLevel(str, Enum):
    NORMAL = "NORMAL"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    EXTREME = "EXTREME"


@dataclass
class AnomalyResult:
    novelty: float            # 0 (typical) … 1 (never seen before)
    score: float              # raw IsolationForest score_samples value
    level: AnomalyLevel
    is_anomalous: bool        # True for CRITICAL / EXTREME
    explanation: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["level"] = self.level.value
        return d


def get_embedder() -> Callable[[str], np.ndarray]:
    """Reuse MiniLM with a bounded exact-text cache.

    The cache helps only byte-identical normalized strings; it does not perform
    semantic or near-duplicate lookup.
    """
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from Autobot.VectorDB.NullPoint_Vector import generate_embedding
        base = generate_embedding
    except Exception as e:  # pragma: no cover
        logger.info("Falling back to local SentenceTransformer (%s)", e)
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer("all-MiniLM-L6-v2")
        base = lambda text: np.asarray(_model.encode(text or ""), dtype=np.float32)

    from functools import lru_cache
    maxsize = int(__import__("os").getenv("EMBED_CACHE_SIZE", "8192"))

    @lru_cache(maxsize=maxsize)
    def _cached(text: str) -> tuple:
        return tuple(np.asarray(base(text or ""), dtype=np.float32).tolist())

    return lambda text: np.asarray(_cached(text or ""), dtype=np.float32)


def _identity_text(data) -> str:
    return data if isinstance(data, str) else ""


class EmbeddingAnomalyDetector:
    """
    One IsolationForest over the embeddings of a single channel's normal traffic.

    text_fn(record) -> str maps a channel record to the text we embed. It is NOT
    pickled (it may close over heavy imports); it is re-attached on load.
    """

    def __init__(self, *, name: str = "email",
                 text_fn: Optional[Callable[[object], str]] = None,
                 contamination: float = 0.05, n_estimators: int = 200,
                 random_state: int = 42):
        self.name = name
        self.text_fn = text_fn or _identity_text
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self._if: Optional[IsolationForest] = None
        self._quantiles: dict = {}
        self._embed = None

    # ------------------------------------------------------------ embedding
    def _embedder(self):
        if self._embed is None:
            self._embed = get_embedder()
        return self._embed

    def _embed_many(self, texts: List[str]) -> np.ndarray:
        embed = self._embedder()
        return np.vstack([np.asarray(embed(t), dtype=np.float32) for t in texts])

    # ------------------------------------------------------------------ fit
    def fit(self, normal_texts: List[str]) -> "EmbeddingAnomalyDetector":
        texts = [t for t in normal_texts if t and t.strip()][:_MAX_FIT_SAMPLES]
        if len(texts) < 20:
            raise ValueError(
                f"[{self.name}] need >=20 normal texts to fit (got {len(texts)})")
        X = self._embed_many(texts)
        self._if = IsolationForest(
            contamination=self.contamination, n_estimators=self.n_estimators,
            random_state=self.random_state, n_jobs=-1,
        ).fit(X)
        scores = self._if.score_samples(X)
        self._quantiles = {
            "q01": float(np.percentile(scores, 1)),
            "q05": float(np.percentile(scores, 5)),
            "q25": float(np.percentile(scores, 25)),
            "q50": float(np.percentile(scores, 50)),
            "min": float(scores.min()),
            "max": float(scores.max()),
        }
        logger.info("[%s] anomaly detector fit on %d normal texts (q05=%.3f)",
                    self.name, len(texts), self._quantiles["q05"])
        return self

    # ---------------------------------------------------------------- score
    def score(self, data) -> AnomalyResult:
        if self._if is None:
            return AnomalyResult(0.0, 0.0, AnomalyLevel.NORMAL, False,
                                 "anomaly detector not fitted")
        text = data if isinstance(data, str) else self.text_fn(data)
        if not text:
            return AnomalyResult(0.0, 0.0, AnomalyLevel.NORMAL, False, "empty text")

        score = float(self._if.score_samples(self._embed_many([text]))[0])
        q = self._quantiles
        spread = max(q["q50"] - q["min"], 1e-6)
        novelty = float(np.clip((q["q50"] - score) / spread, 0.0, 1.0))

        if score < q["q01"]:
            level = AnomalyLevel.EXTREME
        elif score < q["q05"]:
            level = AnomalyLevel.CRITICAL
        elif score < q["q25"]:
            level = AnomalyLevel.WARNING
        else:
            level = AnomalyLevel.NORMAL

        is_anom = level in (AnomalyLevel.CRITICAL, AnomalyLevel.EXTREME)
        explanation = (
            f"{level.value}: {self.name} message sits at novelty {novelty:.0%} "
            f"vs the known-good manifold (score {score:.3f}, p05={q['q05']:.3f})"
        )
        return AnomalyResult(novelty, score, level, is_anom, explanation)

    # ----------------------------------------------------------- persistence
    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({"if": self._if, "quantiles": self._quantiles,
                         "contamination": self.contamination, "name": self.name}, f)
        logger.info("[%s] anomaly detector saved -> %s", self.name, path)

    @classmethod
    def load(cls, path: Path, *, name: str = "email",
             text_fn: Optional[Callable[[object], str]] = None
             ) -> Optional["EmbeddingAnomalyDetector"]:
        if not Path(path).exists():
            return None
        try:
            from common.ml.channel_detector import verify_model_artifact
            digest_env = {
                "email": "PHISH_ANOMALY_SHA256",
                "smishing": "SMISH_ANOMALY_SHA256",
                "vishing": "VISH_ANOMALY_SHA256",
            }.get(name, f"{name.upper()}_ANOMALY_SHA256")
            verify_model_artifact(path, digest_env)
            with open(path, "rb") as f:
                blob = pickle.load(f)
            inst = cls(name=blob.get("name", name), text_fn=text_fn,
                       contamination=blob.get("contamination", 0.05))
            inst._if = blob["if"]
            inst._quantiles = blob["quantiles"]
            return inst
        except Exception as e:
            logger.error("[%s] failed to load anomaly detector: %s", name, e)
            return None


# ---------------------------------------------------------------------------
# Per-channel singleton registry.
# ---------------------------------------------------------------------------
_REGISTRY: dict = {}


def get_channel_anomaly_detector(
    channel: str, *,
    text_fn: Callable[[object], str],
    normal_corpus_fn: Callable[[], List[str]],
    model_path: Path,
    contamination: float = 0.05,
    allow_fit: bool = True,
    refit: bool = False,
) -> Optional[EmbeddingAnomalyDetector]:
    """
    Load (or fit+persist) the anomaly detector for one channel.

    allow_fit=False is the REQUEST hot-path guard: if nothing is cached/on-disk,
    return None and let the caller degrade to classifier-only rather than block
    a live request on a fit.
    """
    if channel in _REGISTRY and not refit:
        return _REGISTRY[channel]
    if not refit:
        loaded = EmbeddingAnomalyDetector.load(model_path, name=channel, text_fn=text_fn)
        if loaded is not None:
            _REGISTRY[channel] = loaded
            return loaded
    if not allow_fit:
        return None
    from common.config import is_production_environment
    if is_production_environment():
        logger.error("[%s] runtime anomaly fitting is disabled in production", channel)
        return None
    det = EmbeddingAnomalyDetector(name=channel, text_fn=text_fn, contamination=contamination)
    det.fit(normal_corpus_fn())
    det.save(model_path)
    _REGISTRY[channel] = det
    return det
