"""Shared promote/hold decision for channel trainers (phish + smish/vish).

Keeps gate semantics per-channel while DRY-ing the force / no-champion /
regression scaffolding. Callers supply their own `passes_gate` result and which
primary metric must not regress (pump_fake_recall vs recall).
"""
from __future__ import annotations

from typing import Dict, Tuple

_REGRESSION_EPS = 0.01


def decide_promotion(
    cand: Dict,
    champ: Dict,
    force: bool,
    *,
    gate_ok: bool,
    gate_fail_reason: str,
    primary_key: str,
    primary_eps: float = _REGRESSION_EPS,
) -> Tuple[bool, str]:
    """Return (promoted, reason). Semantics match the historical trainers.

    Regression if any of:
      - primary metric drops by more than primary_eps (phish pump uses 0)
      - FPR rises by more than _REGRESSION_EPS
      - accuracy drops by more than _REGRESSION_EPS
    """
    if not gate_ok:
        return False, gate_fail_reason
    # A break-glass override may waive the champion-regression comparison, but
    # never the safety/evidence gate itself.
    if force:
        return True, "force_promote_after_gate"
    if not champ:
        return True, "no champion → promote first passing model"

    primary_drop = float(cand.get(primary_key, 0)) < float(champ.get(primary_key, 0)) - primary_eps
    fpr_rise = float(cand.get("fpr", 1)) > float(champ.get("fpr", 1)) + _REGRESSION_EPS
    acc_drop = float(cand.get("accuracy", 0)) < float(champ.get("accuracy", 0)) - _REGRESSION_EPS
    if primary_drop or fpr_rise or acc_drop:
        return False, (
            f"regression vs champion "
            f"(cand {primary_key}={cand.get(primary_key, 0):.3f} "
            f"fpr={cand.get('fpr', 1):.3f} "
            f"vs champ {primary_key}={champ.get(primary_key, 0):.3f} "
            f"fpr={champ.get('fpr', 1):.3f})"
        )
    return True, (
        f"improves/holds ({primary_key} {champ.get(primary_key, 0):.3f}"
        f"→{cand.get(primary_key, 0):.3f}, "
        f"fpr {champ.get('fpr', 1):.3f}→{cand.get('fpr', 1):.3f})"
    )
