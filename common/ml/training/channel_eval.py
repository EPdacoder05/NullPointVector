"""
Channel-agnostic golden evaluation + promotion gate.

Loads a held-out golden set (JSON Lines) and scores any detector-like object
(anything exposing ``.predict(record) -> (pred, conf)``) against it, producing the
metrics the trainer gates on. Includes Wilson confidence intervals on recall/FPR
so an expanded R3 golden set can report "recall 95% (±N)" instead of a bare point
estimate that could be luck on 16 samples.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Callable, List, Tuple

# Default promotion thresholds. Voice/SMS fraud is high-cost to miss, so we gate
# primarily on recall while holding false positives low. Override per channel.
DEFAULT_MIN_RECALL = 0.90
DEFAULT_MAX_FPR = 0.05
DEFAULT_MIN_ACCURACY = 0.90


def load_golden(path: Path | str) -> List[dict]:
    """Load a golden JSONL file → list of records (each must carry an int label)."""
    path = Path(path)
    rows: List[dict] = []
    if not path.exists():
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "label" in rec:
                rows.append(rec)
    return rows


def _wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson score 95% interval for a proportion k/n (stable for small n)."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def evaluate(detector, rows: List[dict] | None = None,
             golden_path: Path | str | None = None) -> dict:
    """Score ``detector`` over the golden set → metrics dict.

    ``detector`` only needs ``.predict(record) -> (pred, conf)``; this works for
    both a live ChannelDetector and a candidate-artifact adapter.
    """
    if rows is None:
        rows = load_golden(golden_path) if golden_path else []
    tp = tn = fp = fn = 0
    inference_errors = 0
    failures: List[dict] = []
    for index, rec in enumerate(rows):
        label = int(rec.get("label", 0))
        try:
            pred, conf = detector.predict(rec)
        except Exception as exc:
            # Offline evaluation must fail closed. Treating an exception as a
            # safe prediction can award a true negative and promote a broken
            # model. Count the row as wrong and invalidate the whole run.
            inference_errors += 1
            if label == 1:
                fn += 1
            else:
                fp += 1
            failures.append({
                "type": "inference_error",
                "index": index,
                "error_type": type(exc).__name__,
            })
            continue
        pred = int(pred)
        if pred == 1 and label == 1:
            tp += 1
        elif pred == 0 and label == 0:
            tn += 1
        elif pred == 1 and label == 0:
            fp += 1
            failures.append({"type": "false_positive", "rec": rec, "conf": conf})
        else:
            fn += 1
            failures.append({"type": "false_negative", "rec": rec, "conf": conf})

    n = tp + tn + fp + fn
    pos = tp + fn
    neg = tn + fp
    accuracy = (tp + tn) / n if n else 0.0
    recall = tp / pos if pos else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    fpr = fp / neg if neg else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    recall_lo, recall_hi = _wilson(tp, pos)
    fpr_lo, fpr_hi = _wilson(fp, neg)

    return {
        "n": n, "accuracy": accuracy, "recall": recall, "precision": precision,
        "fpr": fpr, "f1": f1,
        "recall_ci95": [round(recall_lo, 4), round(recall_hi, 4)],
        "fpr_ci95": [round(fpr_lo, 4), round(fpr_hi, 4)],
        "inference_errors": inference_errors,
        "evaluation_valid": inference_errors == 0,
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "failures": failures,
    }


def passes_gate(metrics: dict, *, min_recall: float = DEFAULT_MIN_RECALL,
                max_fpr: float = DEFAULT_MAX_FPR,
                min_accuracy: float = DEFAULT_MIN_ACCURACY) -> bool:
    """A candidate clears the gate iff it meets recall / FPR / accuracy floors."""
    return (metrics.get("evaluation_valid", True) is True
            and int(metrics.get("inference_errors", 0) or 0) == 0
            and metrics.get("recall", 0.0) >= min_recall
            and metrics.get("fpr", 1.0) <= max_fpr
            and metrics.get("accuracy", 0.0) >= min_accuracy)


def confidence_intervals(metrics: dict) -> Tuple[Tuple[float, float], Tuple[float, float]]:
    """Return recall/FPR Wilson intervals, deriving them from confusion counts.

    Stored snapshots predate interval fields. Deriving from their confusion
    matrix lets the UI reassess evidence without loading a model or rewriting a
    historical score.
    """
    confusion = metrics.get("confusion") or {}
    tp = int(confusion.get("tp", 0) or 0)
    fn = int(confusion.get("fn", 0) or 0)
    fp = int(confusion.get("fp", 0) or 0)
    tn = int(confusion.get("tn", 0) or 0)
    recall_ci = metrics.get("recall_ci95")
    fpr_ci = metrics.get("fpr_ci95")
    if not recall_ci:
        recall_ci = _wilson(tp, tp + fn)
    if not fpr_ci:
        fpr_ci = _wilson(fp, fp + tn)
    return ((float(recall_ci[0]), float(recall_ci[1])),
            (float(fpr_ci[0]), float(fpr_ci[1])))


def has_release_evidence(metrics: dict, *, min_recall: float = DEFAULT_MIN_RECALL,
                         max_fpr: float = DEFAULT_MAX_FPR) -> bool:
    """Whether 95% confidence bounds support the advertised action thresholds."""
    if metrics.get("evaluation_valid", True) is not True:
        return False
    confusion = metrics.get("confusion") or {}
    if not confusion or (int(confusion.get("tp", 0) or 0)
                         + int(confusion.get("fn", 0) or 0) == 0):
        return False
    if int(confusion.get("tn", 0) or 0) + int(confusion.get("fp", 0) or 0) == 0:
        return False
    recall_ci, fpr_ci = confidence_intervals(metrics)
    return recall_ci[0] >= min_recall and fpr_ci[1] <= max_fpr
