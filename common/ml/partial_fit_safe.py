"""Safe single-sample SGD partial_fit.

sklearn's ``class_weight='balanced'`` recomputes weights from *this batch's* ``y``.
A one-row feedback sample only has label 0 *or* 1, so ``compute_class_weight``
raises ``ValueError: classes should have valid labels that are in y``.

For the ephemeral nudge we temporarily clear ``class_weight`` for that step.
Full retrain (ChannelTrainer) still uses balanced weights on a multi-class batch.
"""
from __future__ import annotations

from typing import Any


def partial_fit_one(clf: Any, X, label: int) -> None:
    """One gradient step on a single labeled row; classes fixed to {0, 1}."""
    y = [int(label)]
    prev = getattr(clf, "class_weight", None)
    try:
        if prev is not None:
            clf.class_weight = None
        clf.partial_fit(X, y, classes=[0, 1])
    finally:
        if prev is not None:
            clf.class_weight = prev
