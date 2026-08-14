"""Single-pass evaluation for the vishing action challenge.

This module is intentionally independent of the binary vishing golden set and
model runtime.  It never imports or loads classifier artifacts, and its output
is descriptive challenge evidence only--never release or promotion evidence.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping


ACTIONS = ("allow", "label", "silence", "block")
TAXONOMIES = ("legit", "nuisance_robocall", "fraud")


def load_action_challenge(path: Path | str) -> tuple[dict, list[dict]]:
    """Load a challenge fixture while enforcing its non-training contract."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("action challenge must be a JSON object")
    if payload.get("purpose") != "action_challenge":
        raise ValueError("fixture is not marked as an action challenge")
    if payload.get("training_eligible") is not False:
        raise ValueError("action challenge must be ineligible for training")
    if payload.get("release_evidence") is not False:
        raise ValueError("action challenge cannot be release evidence")

    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise ValueError("action challenge rows must be a list")
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("every action challenge row must be an object")
    if any("label" in row for row in rows):
        raise ValueError("binary labels are forbidden in the action challenge")
    return payload, rows


def _record_failure(
    failures: list[dict],
    *,
    total_failures: int,
    max_failure_details: int,
    detail: dict,
) -> int:
    """Count every failure while bounding retained diagnostic details."""
    total_failures += 1
    if len(failures) < max_failure_details:
        failures.append(detail)
    return total_failures


def _predict_action(predictor: Any, row: Mapping[str, Any]) -> Any:
    if callable(predictor):
        return predictor(row)
    method = getattr(predictor, "predict_action", None)
    if not callable(method):
        raise TypeError("predictor must be callable or expose predict_action")
    return method(row)


def evaluate_actions(
    predictor: Any,
    rows: Iterable[Mapping[str, Any]],
    *,
    training_group_ids: Iterable[str],
    max_failure_details: int = 25,
) -> dict:
    """Evaluate exact policy actions in one pass over ``rows``.

    ``training_group_ids`` is mandatory so callers cannot silently omit the
    train/evaluation leakage check.  Counters are updated in O(1) per row.  The
    retained failure list is bounded; record/group identity sets use O(n)
    memory to enforce uniqueness and group separation.
    """
    if max_failure_details < 0:
        raise ValueError("max_failure_details cannot be negative")

    train_groups = {str(group_id) for group_id in training_group_ids}
    seen_record_ids: set[str] = set()
    eval_groups: set[str] = set()
    overlap_groups: set[str] = set()
    action_support: Counter[str] = Counter()
    taxonomy_support: Counter[str] = Counter()
    predicted_support: Counter[str] = Counter()
    action_confusion = {action: Counter() for action in ACTIONS}

    failures: list[dict] = []
    failure_count = 0
    input_count = 0
    prediction_count = 0
    prediction_errors = 0
    inference_errors = 0
    record_errors = 0
    correct = 0
    false_blocks = 0
    legit_false_blocks = 0

    for row in rows:
        input_count += 1
        record_id = row.get("id")
        group_id = row.get("group_id")
        taxonomy = row.get("taxonomy")
        expected = row.get("expected_action")

        if not isinstance(record_id, str) or not record_id:
            record_errors += 1
            failure_count = _record_failure(
                failures,
                total_failures=failure_count,
                max_failure_details=max_failure_details,
                detail={"type": "invalid_record", "reason": "missing_id"},
            )
            continue
        if record_id in seen_record_ids:
            record_errors += 1
            failure_count = _record_failure(
                failures,
                total_failures=failure_count,
                max_failure_details=max_failure_details,
                detail={"type": "invalid_record", "id": record_id,
                        "reason": "duplicate_id"},
            )
            continue
        seen_record_ids.add(record_id)

        if not isinstance(group_id, str) or not group_id:
            record_errors += 1
            failure_count = _record_failure(
                failures,
                total_failures=failure_count,
                max_failure_details=max_failure_details,
                detail={"type": "invalid_record", "id": record_id,
                        "reason": "missing_group_id"},
            )
            continue
        eval_groups.add(group_id)

        if taxonomy not in TAXONOMIES or expected not in ACTIONS:
            record_errors += 1
            failure_count = _record_failure(
                failures,
                total_failures=failure_count,
                max_failure_details=max_failure_details,
                detail={"type": "invalid_record", "id": record_id,
                        "reason": "invalid_taxonomy_or_expected_action"},
            )
            continue

        taxonomy_support[taxonomy] += 1
        action_support[expected] += 1

        if group_id in train_groups:
            overlap_groups.add(group_id)
            action_confusion[expected]["invalid"] += 1
            record_errors += 1
            failure_count = _record_failure(
                failures,
                total_failures=failure_count,
                max_failure_details=max_failure_details,
                detail={"type": "group_overlap", "id": record_id,
                        "group_id": group_id},
            )
            continue

        try:
            predicted = _predict_action(predictor, row)
        except Exception as exc:
            inference_errors += 1
            action_confusion[expected]["invalid"] += 1
            failure_count = _record_failure(
                failures,
                total_failures=failure_count,
                max_failure_details=max_failure_details,
                detail={"type": "inference_error", "id": record_id,
                        "error_type": type(exc).__name__},
            )
            continue

        if predicted not in ACTIONS:
            prediction_errors += 1
            action_confusion[expected]["invalid"] += 1
            failure_count = _record_failure(
                failures,
                total_failures=failure_count,
                max_failure_details=max_failure_details,
                detail={"type": "invalid_prediction", "id": record_id,
                        "prediction_type": type(predicted).__name__},
            )
            continue

        prediction_count += 1
        predicted_support[predicted] += 1
        action_confusion[expected][predicted] += 1
        if predicted == expected:
            correct += 1
        if predicted == "block" and expected != "block":
            false_blocks += 1
            if taxonomy == "legit":
                legit_false_blocks += 1

    valid_expected_count = sum(action_support.values())
    non_block_support = (
        action_support["allow"]
        + action_support["label"]
        + action_support["silence"]
    )
    legit_support = taxonomy_support["legit"]
    accuracy = correct / valid_expected_count if valid_expected_count else 0.0

    per_action: dict[str, dict] = {}
    for action in ACTIONS:
        true_positive = action_confusion[action][action]
        false_positive = predicted_support[action] - true_positive
        false_negative = action_support[action] - true_positive
        per_action[action] = {
            "support": action_support[action],
            "predicted": predicted_support[action],
            "tp": true_positive,
            "fp": false_positive,
            "fn": false_negative,
            "precision": (
                true_positive / predicted_support[action]
                if predicted_support[action]
                else 0.0
            ),
            "recall": (
                true_positive / action_support[action]
                if action_support[action]
                else 0.0
            ),
        }

    if input_count == 0:
        record_errors += 1
        failure_count = _record_failure(
            failures,
            total_failures=failure_count,
            max_failure_details=max_failure_details,
            detail={"type": "empty_evaluation"},
        )

    evaluation_valid = (
        input_count > 0
        and record_errors == 0
        and prediction_errors == 0
        and inference_errors == 0
        and not overlap_groups
    )
    return {
        "challenge_only": True,
        "release_evidence": False,
        "evaluation_valid": evaluation_valid,
        "expectations_met": evaluation_valid and correct == input_count,
        "accuracy": accuracy,
        "group_disjoint": not overlap_groups,
        "false_block_count": false_blocks,
        "false_block_rate": (
            false_blocks / non_block_support if non_block_support else 0.0
        ),
        "legit_false_block_count": legit_false_blocks,
        "legit_false_block_rate": (
            legit_false_blocks / legit_support if legit_support else 0.0
        ),
        "per_action": per_action,
        "confusion": {
            "allow": dict(action_confusion["allow"]),
            "label": dict(action_confusion["label"]),
            "silence": dict(action_confusion["silence"]),
            "block": dict(action_confusion["block"]),
        },
        "evidence": {
            "input_count": input_count,
            "valid_expected_count": valid_expected_count,
            "prediction_count": prediction_count,
            "unique_group_count": len(eval_groups),
            "training_group_count": len(train_groups),
            "taxonomy_support": dict(taxonomy_support),
            "expected_action_support": dict(action_support),
        },
        "record_errors": record_errors,
        "prediction_errors": prediction_errors,
        "inference_errors": inference_errors,
        "failure_count": failure_count,
        "failures": failures,
        "overlap_group_ids": sorted(overlap_groups),
    }
