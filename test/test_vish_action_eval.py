"""Action challenge harness tests; no vishing model artifacts are imported."""
from pathlib import Path

from common.vish.action_eval import evaluate_actions, load_action_challenge


FIXTURE = Path(__file__).parent / "fixtures" / "vish_action_challenge.json"


def _load_rows():
    metadata, rows = load_action_challenge(FIXTURE)
    return metadata, rows


def test_fixture_is_balanced_challenge_only_and_has_no_binary_labels():
    metadata, rows = _load_rows()
    taxonomy_counts = {}
    action_counts = {}
    for row in rows:
        taxonomy = row["taxonomy"]
        action = row["expected_action"]
        taxonomy_counts[taxonomy] = taxonomy_counts.get(taxonomy, 0) + 1
        action_counts[action] = action_counts.get(action, 0) + 1
        assert "label" not in row
        assert row["group_id"].startswith("challenge-")

    assert metadata["training_eligible"] is False
    assert metadata["release_evidence"] is False
    assert taxonomy_counts == {
        "legit": 4,
        "nuisance_robocall": 8,
        "fraud": 4,
    }
    assert action_counts == {"allow": 4, "label": 4, "silence": 4, "block": 4}
    assert taxonomy_counts["legit"] == taxonomy_counts["fraud"]


def test_single_pass_perfect_action_report_is_still_not_release_evidence():
    _, rows = _load_rows()

    class SinglePassRows:
        def __init__(self, records):
            self.records = records
            self.iterations = 0

        def __iter__(self):
            self.iterations += 1
            assert self.iterations == 1
            return iter(self.records)

    source = SinglePassRows(rows)
    result = evaluate_actions(
        lambda row: row["expected_action"],
        source,
        training_group_ids={"train-tax-callback", "train-tax-fraud"},
    )

    assert result["evaluation_valid"] is True
    assert result["expectations_met"] is True
    assert result["accuracy"] == 1.0
    assert result["release_evidence"] is False
    assert result["false_block_count"] == 0
    assert result["evidence"]["input_count"] == 16
    assert result["evidence"]["prediction_count"] == 16
    for action in ("allow", "label", "silence", "block"):
        assert result["per_action"][action]["support"] == 4
        assert result["per_action"][action]["tp"] == 4
        assert result["per_action"][action]["fp"] == 0
        assert result["per_action"][action]["fn"] == 0


def test_false_blocks_are_reported_separately_for_legitimate_calls():
    _, rows = _load_rows()

    def overblocking_policy(row):
        if row["taxonomy"] == "legit":
            return "block"
        return row["expected_action"]

    result = evaluate_actions(
        overblocking_policy,
        rows,
        training_group_ids={"train-unrelated"},
    )

    assert result["evaluation_valid"] is True
    assert result["expectations_met"] is False
    assert result["false_block_count"] == 4
    assert result["false_block_rate"] == 4 / 12
    assert result["legit_false_block_count"] == 4
    assert result["legit_false_block_rate"] == 1.0
    assert result["confusion"]["allow"] == {"block": 4}
    assert result["per_action"]["block"]["fp"] == 4


def test_group_overlap_invalidates_evaluation_before_prediction():
    _, rows = _load_rows()
    overlapped_group = rows[0]["group_id"]
    called_ids = []

    def predictor(row):
        called_ids.append(row["id"])
        return row["expected_action"]

    result = evaluate_actions(
        predictor,
        rows,
        training_group_ids={overlapped_group},
    )

    assert result["evaluation_valid"] is False
    assert result["group_disjoint"] is False
    assert result["overlap_group_ids"] == [overlapped_group]
    assert result["failure_count"] == 2
    assert rows[0]["id"] not in called_ids
    assert rows[1]["id"] not in called_ids


def test_invalid_action_and_inference_error_fail_closed():
    _, rows = _load_rows()
    selected = rows[:2]

    def broken_predictor(row):
        if row["id"].endswith("a"):
            return "quarantine"
        raise RuntimeError("sensitive backend detail")

    result = evaluate_actions(
        broken_predictor,
        selected,
        training_group_ids=set(),
    )

    assert result["evaluation_valid"] is False
    assert result["expectations_met"] is False
    assert result["prediction_errors"] == 1
    assert result["inference_errors"] == 1
    assert result["evidence"]["prediction_count"] == 0
    assert result["confusion"]["allow"] == {"invalid": 2}
    assert "sensitive backend detail" not in str(result["failures"])


def test_failure_details_are_bounded_but_all_failures_are_counted():
    _, rows = _load_rows()
    result = evaluate_actions(
        lambda _row: "invalid",
        rows,
        training_group_ids=set(),
        max_failure_details=3,
    )
    assert result["failure_count"] == 16
    assert len(result["failures"]) == 3
