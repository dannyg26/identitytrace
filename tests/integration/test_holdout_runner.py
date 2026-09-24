"""Integration tests against the actual frozen holdout file
(tests/fixtures/holdout/holdout_v1.json) - Phase 9 #6's real exit
criterion. If these ever fail after a code change, that IS the holdout
result changing - see docs/holdout.md for how to record it (never by
editing the frozen file to make the test pass again)."""

from app.evaluation.holdout_runner import load_holdout_dataset, run_holdout_evaluation


def test_frozen_file_loads_and_has_the_expected_shape():
    benign_sequences, instances = load_holdout_dataset()
    assert len(benign_sequences) > 0
    assert len(instances) > 0
    assert any(i.attack_type == "COMBO" for i in instances)
    assert any(s.persona == "shared_workstation" for s in benign_sequences)


def test_holdout_evaluation_runs_end_to_end():
    metrics = run_holdout_evaluation()
    assert metrics["totals"]["attack_scenarios"] > 0
    assert metrics["totals"]["incidents"] > 0


def test_holdout_isolated_recall_is_still_perfect():
    """Every generated attack chain includes at least one atomic-rule-
    triggering event by construction - true on the holdout set for the
    same reason it's true on the main set (scenarios.py's shared
    builders)."""
    metrics = run_holdout_evaluation()
    assert metrics["isolated_rule_baseline"]["recall"] == 1.0


def test_holdout_correlation_has_zero_false_positives():
    """The point of a holdout set: this wasn't tuned to pass this check -
    it's the first time this exact data has ever been run."""
    metrics = run_holdout_evaluation()
    assert metrics["correlation_engine"]["false_positive_incidents"] == 0
    assert metrics["correlation_engine"]["precision"] == 1.0


def test_holdout_novel_combo_attack_is_detected_by_both_layers():
    """The specific, falsifiable prediction holdout.py's docstring makes:
    IDT-CORR-003 should pick out the role-assignment -> sensitive-access
    sub-chain even with an unrelated new-device signin mixed in ahead of
    it, even though this exact combination was never in the main
    generator."""
    metrics = run_holdout_evaluation()
    combo = metrics["scenario_coverage"]["COMBO"]
    assert combo["recall_isolated"] == 1.0
    assert combo["recall_correlated"] == 1.0


def test_holdout_a6_gap_is_consistent_with_the_main_dataset():
    """A6 has no correlation rule by design (see scenarios.py's _make_a6)
    - that should hold on held-out data too, not just the set it was
    designed against."""
    metrics = run_holdout_evaluation()
    assert metrics["scenario_coverage"]["A6"]["recall_correlated"] == 0.0
    assert metrics["scenario_coverage"]["A6"]["recall_isolated"] == 1.0
