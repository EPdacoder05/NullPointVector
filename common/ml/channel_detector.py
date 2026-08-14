"""
Generic channel detector — the reusable core behind SmishGuard & VishGuard.

Architecture (identical to PhishGuard's email detector, generalized):

    text  ─┬─ word TF-IDF (15k, 1-3 grams)   linguistic patterns
           ├─ char TF-IDF (10k, 3-5 grams)   leet/obfuscation: "acc0unt"
           └─ structural numeric features    channel-specific, hard-to-fake
                              ↓ hstack (sparse)
                  SGDClassifier(log_loss, class_weight=balanced)
                              ↓ Platt scaling (A,B)
                       calibrated P(threat)

The only things a channel supplies are:
  - text_fn(record)    -> str        (how to flatten a record into text)
  - numeric_fn(text, record) -> list[float]   (the structural feature vector)
  - num_features       (len of that vector — the feature schema version)
  - seed_fn()          -> list[(record, label)]  (cold-start corpus)

Complexity:  predict O(T + F) per message (T tokens, F structural feats),
sub-millisecond on CPU. partial_fit O(F_total) weight update (~10ms). A full
cold-start refit always replays the seed corpus → no catastrophic forgetting.
"""
from __future__ import annotations

import logging
import hashlib
import hmac
import math
import os
import pickle
import re
from pathlib import Path
from typing import Callable

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier

from common.config import is_production_environment

logger = logging.getLogger(__name__)

# Hyper-parameters live in ONE place (shared with PhishGuard's reference values).
WORD_TFIDF_PARAMS = dict(max_features=15_000, ngram_range=(1, 3),
                         sublinear_tf=True, min_df=1, analyzer="word")
CHAR_TFIDF_PARAMS = dict(max_features=10_000, ngram_range=(3, 5),
                         sublinear_tf=True, min_df=1, analyzer="char_wb")
SGD_PARAMS = dict(loss="log_loss", penalty="l2", max_iter=1000,
                  random_state=42, class_weight="balanced", warm_start=True)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def resolve_model_artifact(default_path: Path | str) -> Path:
    """Resolve a model filename under an optional deploy-only artifact mount."""
    default = Path(default_path)
    configured_root = os.getenv("MODEL_ARTIFACT_DIR", "").strip()
    if not configured_root:
        return default
    root = Path(configured_root)
    if is_production_environment() and not root.is_absolute():
        raise RuntimeError("MODEL_ARTIFACT_DIR must be absolute in production")
    return root / default.name


def verify_model_artifact(path: Path | str, digest_env: str) -> None:
    """Verify an operator-approved digest before unpickling a model artifact.

    Pickle is executable input. Internet-facing deployments therefore require a
    pinned SHA-256 supplied by the deploy secret/config store. Development may
    omit the pin, but an explicitly configured pin is always enforced.
    """
    expected = os.getenv(digest_env, "").strip()
    if not expected:
        if is_production_environment():
            raise RuntimeError(f"{digest_env} is required for model loading")
        return
    if not _SHA256_RE.fullmatch(expected):
        raise RuntimeError(f"{digest_env} must be a 64-character SHA-256 digest")

    digest = hashlib.sha256()
    with Path(path).open("rb") as artifact_file:
        for chunk in iter(lambda: artifact_file.read(1024 * 1024), b""):
            digest.update(chunk)
    if not hmac.compare_digest(digest.hexdigest(), expected.lower()):
        raise RuntimeError("model artifact digest verification failed")


def make_word_tfidf() -> TfidfVectorizer:
    return TfidfVectorizer(**WORD_TFIDF_PARAMS)


def make_char_tfidf() -> TfidfVectorizer:
    return TfidfVectorizer(**CHAR_TFIDF_PARAMS)


def make_classifier() -> SGDClassifier:
    return SGDClassifier(**SGD_PARAMS)


def stack_versions() -> dict:
    """Capture the ML stack versions an artifact was trained under.

    Stamped into every artifact so train/serve skew is *visible* (logged) instead
    of silently triggering a per-boot cold-start retrain. Reproducibility hinges
    on the runtime matching these — see Dockerfile's pinned ML layer.
    """
    import numpy
    import scipy
    import sklearn
    return {"sklearn": sklearn.__version__, "numpy": numpy.__version__,
            "scipy": scipy.__version__}


def build_feature_matrix(word_tfidf, char_tfidf, texts, metas, numeric_fn, fit=False):
    """Fuse word + char TF-IDF + structural features into one sparse matrix."""
    if fit:
        x_word = word_tfidf.fit_transform(texts)
        x_char = char_tfidf.fit_transform(texts)
    else:
        x_word = word_tfidf.transform(texts)
        x_char = char_tfidf.transform(texts)
    x_num = csr_matrix(np.array(
        [numeric_fn(t, m) for t, m in zip(texts, metas)], dtype=np.float32))
    return hstack([x_word, x_char, x_num]).tocsr()


def build_artifact(texts, labels, metas, numeric_fn, num_features, calibrate=False) -> dict:
    """Train a fresh, self-contained artifact from scratch (full refit)."""
    word_tfidf, char_tfidf, clf = make_word_tfidf(), make_char_tfidf(), make_classifier()
    X = build_feature_matrix(word_tfidf, char_tfidf, texts, metas, numeric_fn, fit=True)
    clf.fit(X, labels)

    platt = None
    if calibrate and len(set(labels)) == 2 and len(labels) >= 50:
        try:
            margins = clf.decision_function(X).reshape(-1, 1)
            lr = LogisticRegression(max_iter=1000)
            lr.fit(margins, labels)
            platt = (float(lr.coef_[0, 0]), float(lr.intercept_[0]))
        except Exception as e:  # pragma: no cover - calibration is best-effort
            logger.warning("Platt calibration skipped: %s", e)

    return {"word_tfidf": word_tfidf, "char_tfidf": char_tfidf, "clf": clf,
            "platt": platt, "feature_version": num_features,
            "stack": stack_versions()}


def predict_with(artifact, text, meta, numeric_fn, threshold=0.5) -> tuple[int, float]:
    """Stateless prediction against an artifact. Fail-safe → (0, 0.0)."""
    clf = artifact.get("clf")
    if clf is None or not text:
        return (0, 0.0)
    try:
        X = build_feature_matrix(
            artifact["word_tfidf"], artifact["char_tfidf"], [text], [meta], numeric_fn)
        platt = artifact.get("platt")
        if platt:
            a, b = platt
            margin = float(clf.decision_function(X)[0])
            p1 = 1.0 / (1.0 + math.exp(-(a * margin + b)))
            proba = (1.0 - p1, p1)
        else:
            proba = clf.predict_proba(X)[0]
        pred = int(proba[1] >= threshold)
        return pred, float(proba[pred])
    except Exception as e:
        logger.error("predict_with failed: %s", e)
        return (0, 0.0)


class ChannelDetector:
    """
    Per-channel detector with the same lifecycle as PhishGuard:
    load-or-cold-start, calibrated predict, and safe ephemeral online learning.

    It exposes ``.predict(record)`` and ``.clf`` so it is a drop-in ``detector``
    for ``PhishGuard.phish_mlm.risk.assess`` (the unified classifier + anomaly
    verdict engine is channel-agnostic).
    """

    def __init__(self, *, name: str, model_path: Path | str,
                 text_fn: Callable[[dict], str],
                 numeric_fn: Callable[[str, dict], list],
                 num_features: int,
                 seed_fn: Callable[[], list],
                 artifact_digest_env: str,
                 threshold: float = 0.5):
        self.name = name
        self.model_path = Path(model_path)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self.text_fn = text_fn
        self.numeric_fn = numeric_fn
        self.num_features = num_features
        self.seed_fn = seed_fn
        self.artifact_digest_env = artifact_digest_env
        self.threshold = threshold

        self.word_tfidf = None
        self.char_tfidf = None
        self.clf = None
        self.platt = None
        self._initialize_model()

    # ----------------------------------------------------------- artifact bridge
    @property
    def _artifact(self) -> dict:
        return {"word_tfidf": self.word_tfidf, "char_tfidf": self.char_tfidf,
                "clf": self.clf, "platt": self.platt,
                "feature_version": self.num_features,
                "stack": stack_versions()}

    def load_artifact(self, artifact: dict):
        self.word_tfidf = artifact["word_tfidf"]
        self.char_tfidf = artifact["char_tfidf"]
        self.clf = artifact["clf"]
        self.platt = artifact.get("platt")

    # ----------------------------------------------------------- lifecycle
    def _initialize_model(self):
        production = is_production_environment()
        if self.model_path.exists():
            try:
                verify_model_artifact(self.model_path, self.artifact_digest_env)
                with open(self.model_path, "rb") as f:
                    saved = pickle.load(f)
                if saved.get("feature_version") != self.num_features:
                    raise RuntimeError(
                        f"{self.name}: model feature schema does not match runtime"
                    )
                want, have = saved.get("stack"), stack_versions()
                if production and not want:
                    raise RuntimeError(f"{self.name}: model stack metadata is missing")
                if want != have:
                    if production:
                        raise RuntimeError(
                            f"{self.name}: model training stack does not match runtime"
                        )
                    logger.warning("%s: artifact stack skew trained=%s runtime=%s "
                                   "(pin the ML stack to match)", self.name, want, have)
                self.load_artifact(saved)
                logger.info("%s: loaded model (calibrated=%s, stack=%s)",
                            self.name, self.platt is not None, saved.get("stack"))
                return
            except Exception as e:
                if production:
                    raise RuntimeError(
                        f"{self.name}: approved model artifact is unavailable"
                    ) from e
                logger.error("%s: failed to load model (%s) — retraining", self.name, e)
        elif production:
            raise RuntimeError(f"{self.name}: model artifact is required in production")
        self._cold_start_training()

    def _cold_start_training(self):
        data = self.seed_fn()
        texts = [self.text_fn(rec) for rec, _ in data]
        metas = [rec for rec, _ in data]
        labels = [int(lbl) for _, lbl in data]
        artifact = build_artifact(texts, labels, metas, self.numeric_fn,
                                  self.num_features, calibrate=True)
        self.load_artifact(artifact)
        self._save_model()
        logger.info("%s: cold-start trained on %d examples (calibrated=%s)",
                    self.name, len(labels), self.platt is not None)

    def _save_model(self):
        if is_production_environment():
            raise RuntimeError("runtime model writes are disabled in production")
        try:
            with open(self.model_path, "wb") as f:
                pickle.dump(self._artifact, f)
        except Exception as e:
            logger.error("%s: failed to save model: %s", self.name, e)

    # ----------------------------------------------------------- inference
    def predict(self, record: dict) -> tuple[int, float]:
        text = self.text_fn(record)
        return predict_with(self._artifact, text, record, self.numeric_fn, self.threshold)

    def learn_from_feedback(self, record: dict, is_threat: bool):
        """
        SAFE online update: ephemeral in-memory ``partial_fit`` only. The on-disk
        model is NOT mutated here — durable change happens through a gated retrain
        (mirrors PhishGuard's feedback-buffer discipline, no live poisoning).
        """
        if self.clf is None:
            return
        try:
            text = self.text_fn(record)
            X = build_feature_matrix(
                self.word_tfidf, self.char_tfidf, [text], [record], self.numeric_fn)
            from common.ml.partial_fit_safe import partial_fit_one
            partial_fit_one(self.clf, X, int(bool(is_threat)))
        except Exception as e:
            logger.error("%s: online update failed: %s", self.name, e)
            raise
