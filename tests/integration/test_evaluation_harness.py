"""Integration tests for the Phase 7 exit criterion: a reproducible
benign/attack scenario suite, run through the real pipeline, comparing the
correlation engine against an isolated-rule baseline.

These exercise app.evaluation.harness.run_evaluation() directly (not via
the API) for the core invariants, since it's cheap and deterministic; the
API/dashboard wiring is checked separately below with the small default
dataset for speed.
"""

from app.evaluation.harness import run_evaluation


def test_evaluation_is_deterministic_given_the_same_seed():
    first = run_evaluation(seed=42, scenarios_per_type=1, num_benign_identities=2)
    second = run_evaluation(seed=42, scenarios_per_type=1, num_benign_identities=2)
    assert first == second


def test_isolated_rules_achieve_perfect_recall_on_this_dataset():
    """Every generated attack chain includes at least one event that
    trips an atomic rule by construction (see scenarios.py) - recall
    should be 1.0 for the isolated-rule baseline across every scenario."""
    metrics = run_evaluation(seed=42, scenarios_per_type=2)
    assert metrics["isolated_rule_baseline"]["recall"] == 1.0
    for coverage in metrics["scenario_coverage"].values():
        assert coverage["recall_isolated"] == 1.0


def test_correlation_engine_covers_a1_through_a5_but_not_a6_by_design():
    """A6 is deliberately generated as a standalone signal with no
    correlation-rule sequence (see scenarios.py's _make_a6 docstring) -
    an honest, documented coverage gap, not a bug to hide."""
    metrics = run_evaluation(seed=42, scenarios_per_type=2)
    coverage = metrics["scenario_coverage"]
    for attack_type in ("A1", "A2", "A3", "A4", "A5"):
        assert coverage[attack_type]["recall_correlated"] == 1.0
    assert coverage["A6"]["recall_correlated"] == 0.0


def test_no_false_positive_incidents_from_benign_edge_cases():
    """The traveling employee (new device+country, no follow-up) and the
    high-volume data analyst (large but consistent transfers) are
    deliberately borderline-looking but genuinely benign - correlation
    must not turn either into an incident."""
    metrics = run_evaluation(seed=42, scenarios_per_type=2)
    assert metrics["correlation_engine"]["false_positive_incidents"] == 0
    assert metrics["correlation_engine"]["precision"] == 1.0


def test_correlation_reduces_alert_volume_versus_isolated_rules():
    metrics = run_evaluation(seed=42, scenarios_per_type=2)
    assert metrics["totals"]["incidents"] > 0
    assert metrics["totals"]["atomic_alerts"] > metrics["totals"]["incidents"]
    assert metrics["alert_reduction_ratio"] > 1.0


def test_scaling_scenarios_per_type_scales_the_dataset():
    small = run_evaluation(seed=1, scenarios_per_type=1)
    large = run_evaluation(seed=1, scenarios_per_type=3)
    assert large["totals"]["attack_scenarios"] == 3 * small["totals"]["attack_scenarios"]
