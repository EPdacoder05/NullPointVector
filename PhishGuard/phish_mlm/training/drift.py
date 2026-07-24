"""
Data & concept drift monitoring.

Two complementary signals:
  1. Feature drift  — Population Stability Index (PSI) on the 26 structural
     features. Detects when the *input distribution* shifts (e.g. attackers
     switch from .ru links to compromised .com domains).
  2. Confidence drift — PSI on the model's predicted probabilities. Detects when
     the model becomes systematically less/more confident (a concept-drift proxy).

PSI interpretation (industry standard):
    < 0.10  → stable        (no action)
    0.10–0.25 → moderate     (watch / schedule retrain)
    ≥ 0.25  → significant    (retrain now; distribution has materially shifted)

Complexity: psi() is O(N) over the batch; DriftMonitor stores O(F * buckets)
bucket edges, so scoring a batch is O(N * F).
"""
import numpy as np
from typing import Dict, List, Optional

_EPS = 1e-6


def psi(expected, actual, buckets: int = 10) -> float:
    """
    Population Stability Index between a reference (`expected`) and a new
    (`actual`) sample of a single feature. Returns 0.0 for a constant reference.
    """
    expected = np.asarray(expected, dtype=float).ravel()
    actual = np.asarray(actual, dtype=float).ravel()
    if expected.size == 0 or actual.size == 0:
        return 0.0

    # Quantile bucket edges from the reference distribution.
    edges = np.unique(np.percentile(expected, np.linspace(0, 100, buckets + 1)))
    if edges.size < 2:
        return 0.0  # constant feature → no drift signal
    edges[0], edges[-1] = -np.inf, np.inf

    e_pct = np.histogram(expected, bins=edges)[0] / expected.size
    a_pct = np.histogram(actual, bins=edges)[0] / actual.size
    e_pct = np.clip(e_pct, _EPS, None)
    a_pct = np.clip(a_pct, _EPS, None)
    return float(np.sum((a_pct - e_pct) * np.log(a_pct / e_pct)))


def classify(score: float) -> str:
    if score >= 0.25:
        return "significant"
    if score >= 0.10:
        return "moderate"
    return "stable"


class DriftMonitor:
    """
    Holds a reference snapshot and scores new batches against it.

    fit(reference_features, reference_conf) once on the training distribution,
    then score(batch_features, batch_conf) on live traffic windows.
    """

    def __init__(self, buckets: int = 10):
        self.buckets = buckets
        self._ref_features: Optional[np.ndarray] = None  # (N, F)
        self._ref_conf: Optional[np.ndarray] = None       # (N,)

    def fit(self, reference_features, reference_conf=None) -> "DriftMonitor":
        self._ref_features = np.asarray(reference_features, dtype=float)
        if self._ref_features.ndim == 1:
            self._ref_features = self._ref_features.reshape(-1, 1)
        self._ref_conf = (np.asarray(reference_conf, dtype=float).ravel()
                          if reference_conf is not None else None)
        return self

    def score(self, batch_features, batch_conf=None) -> Dict:
        """Return per-feature PSI, aggregates, confidence PSI and a verdict."""
        if self._ref_features is None:
            raise RuntimeError("DriftMonitor.fit() must be called before score()")
        batch = np.asarray(batch_features, dtype=float)
        if batch.ndim == 1:
            batch = batch.reshape(-1, 1)

        n_feat = self._ref_features.shape[1]
        per_feature: List[float] = [
            psi(self._ref_features[:, j], batch[:, j], self.buckets)
            for j in range(min(n_feat, batch.shape[1]))
        ]
        max_psi = max(per_feature) if per_feature else 0.0
        mean_psi = float(np.mean(per_feature)) if per_feature else 0.0

        conf_psi = 0.0
        if self._ref_conf is not None and batch_conf is not None:
            conf_psi = psi(self._ref_conf, np.asarray(batch_conf, float), self.buckets)

        overall = max(max_psi, conf_psi)
        return {
            "per_feature_psi": [round(p, 4) for p in per_feature],
            "max_feature_psi": round(max_psi, 4),
            "mean_feature_psi": round(mean_psi, 4),
            "confidence_psi": round(conf_psi, 4),
            "overall_psi": round(overall, 4),
            "level": classify(overall),
            "should_retrain": overall >= 0.25,
        }
