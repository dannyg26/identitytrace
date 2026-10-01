import pytest

from app.evaluation.harness import run_evaluation, run_multi_seed_evaluation
from app.evaluation.metrics import _f1
from app.evaluation.statistics import wilson_interval


def test_f1_zero_when_predictions_and_recall_are_both_wrong():
    assert _f1(0.0, 0.0) == 0.0
    assert _f1(None, 0.0) is None


def test_wilson_interval_known_boundary_and_small_sample():
    assert wilson_interval(0, 0) is None
    assert wilson_interval(0, 10)["upper"] == 0.2775
    assert wilson_interval(10, 10)["lower"] == 0.7225
    interval = wilson_interval(2, 7)
    assert interval["lower"] < 2 / 7 < interval["upper"]
    with pytest.raises(ValueError):
        wilson_interval(3, 2)


def test_benchmark_manifest_repeats_and_workflow_counts_balance():
    a = run_evaluation(seed=19, scenarios_per_type=1, num_benign_identities=1)
    b = run_evaluation(seed=19, scenarios_per_type=1, num_benign_identities=1)
    assert a["provenance"] == b["provenance"]
    assert len(a["provenance"]["dataset_sha256"]) == 64
    for metrics in a["workflow_metrics"].values():
        assert metrics["true_positive_workflows"] + metrics["false_negative_workflows"] == a["totals"]["attack_scenarios"]
        assert metrics["true_negative_workflows"] + metrics["false_positive_workflows"] == a["totals"]["benign_sequences"]
        assert metrics["intervals_95"]["recall"]["trials"] == a["totals"]["attack_scenarios"]


@pytest.mark.parametrize("seeds", [[], [42, 42]])
def test_seed_lists_cannot_silently_duplicate_trials(seeds):
    with pytest.raises(ValueError):
        run_multi_seed_evaluation(seeds)
