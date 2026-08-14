"""
Email (phishing) anomaly detector — a thin channel binding over the shared
`common.ml.anomaly.EmbeddingAnomalyDetector`.

The generic detector + per-channel registry live in common/ml/anomaly.py (single
source of truth). This module only supplies the EMAIL specifics: how to flatten
an email into text, where its manifold is stored, and what its normal corpus is.
SmishGuard/VishGuard supply their own bindings via the same registry.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

# Re-export the shared types so existing imports keep working.
from common.ml.anomaly import (  # noqa: F401
    AnomalyLevel, AnomalyResult, EmbeddingAnomalyDetector,
    get_channel_anomaly_detector,
)
from common.ml.channel_detector import resolve_model_artifact

logger = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent
_MODEL_DIR = _HERE.parent / "models"
_MODEL_DIR.mkdir(parents=True, exist_ok=True)
ANOMALY_MODEL_PATH = resolve_model_artifact(_MODEL_DIR / "anomaly_if.pkl")


def _email_text(data) -> str:
    if isinstance(data, str):
        return data
    import sys
    sys.path.insert(0, str(_HERE.parent))
    from phishing_detector import extract_email_text
    return extract_email_text(data)


def _normal_corpus() -> List[str]:
    import sys
    sys.path.insert(0, str(_HERE.parent))
    from phishing_detector import detector as live_detector, extract_email_text
    texts, labels, _metas = live_detector._seed_corpus()
    normal = [t for t, l in zip(texts, labels) if l == 0]

    ing = _HERE.parent.parent.parent / "data" / "ingestion"
    if ing.exists():
        for fp in sorted(ing.glob("*.json"))[-20:]:
            try:
                for rec in json.loads(fp.read_text()):
                    if isinstance(rec, dict):
                        t = extract_email_text(rec)
                        if t:
                            normal.append(t)
            except Exception:
                continue
    return normal


def get_anomaly_detector(refit: bool = False, allow_fit: bool = True
                         ) -> Optional[EmbeddingAnomalyDetector]:
    """Process-wide email anomaly singleton (delegates to the shared registry)."""
    return get_channel_anomaly_detector(
        "email", text_fn=_email_text, normal_corpus_fn=_normal_corpus,
        model_path=ANOMALY_MODEL_PATH, allow_fit=allow_fit, refit=refit)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    det = get_anomaly_detector(refit=True)
    samples = [
        ("typical legit", {"subject": "Lunch?", "body": "Want to grab lunch Friday at noon?", "from": "alex@gmail.com"}),
        ("known phish", {"subject": "Verify", "body": "Your PayPal is suspended, verify at paypal-secure.ru", "from": "x@paypal-secure.ru"}),
        ("novel/odd", {"subject": "OKR sync", "body": "Bonjour, votre colis attend une confirmation de paiement de 2 euros.", "from": "noreply@colis-relais.fr"}),
    ]
    print("\n=== Email anomaly demo ===")
    for name, email in samples:
        r = det.score(email)
        print(f"  {name:14} -> {r.level.value:8} novelty={r.novelty:.0%}")
