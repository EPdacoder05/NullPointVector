"""
Unsupervised anomaly layer for PhishGuard.

The supervised SGD classifier only catches patterns similar to its training
data. Novel campaigns (new brand, new language, new structure) look "safe" to
it. This layer fits an IsolationForest over MiniLM embeddings of NORMAL email,
so anything far from the known-good manifold is surfaced for human triage —
even when the classifier is confident it is safe. Triaged anomalies feed the
feedback buffer, which the Trainer folds into the next gated retrain. That loop
is the self-improving security platform.
"""
__all__ = ["EmbeddingAnomalyDetector", "AnomalyLevel", "AnomalyResult",
           "get_anomaly_detector"]


def __getattr__(name):
    from . import embedding_anomaly as _m
    if name in __all__:
        return getattr(_m, name)
    raise AttributeError(name)
