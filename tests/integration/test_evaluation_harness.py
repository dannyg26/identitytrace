"""Integration tests for the Phase 7 exit criterion: a reproducible
benign/attack scenario suite, run through the real pipeline, comparing the
correlation engine against an isolated-rule baseline.

These exercise app.evaluation.harness.run_evaluation() directly (not via
the API) for the core invariants, since it's cheap and deterministic; the
API/dashboard wiring is checked separately below with the small default
dataset for speed.
"""

from app.evaluation.harness import run_evaluation, run_multi_seed_evaluation


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
    """None of the six noisy personas (traveling user, legitimate admin,
    developer burst, new laptop, service account, bulk download) or the
    four ambiguous singletons should ever become a false-positive
    incident, no matter how individually alarming their atomic signals
    look - correlation must not turn any of them into an incident."""
    metrics = run_evaluation(seed=42, scenarios_per_type=2)
    assert metrics["correlation_engine"]["false_positive_incidents"] == 0
    assert metrics["correlation_engine"]["precision"] == 1.0
    assert metrics["correlation_engine"]["false_positive_rate"] == 0.0


def test_correlation_is_a_meaningfully_stronger_baseline_under_realistic_noise():
    """Phase 9 #11's actual point: with only clean synthetic data, both
    layers hit 100% precision and the comparison proves nothing. The
    noisy benign personas are realistic enough that isolated atomic
    rules - correctly, not as a bug - fire on several of them (an
    admin's role change, a developer's burst of repo access, a new
    laptop, ...). Correlation should still hold near-perfect precision on
    the exact same dataset, which is the actual research finding, not an
    assumption."""
    metrics = run_evaluation(seed=42, scenarios_per_type=2)
    isolated = metrics["isolated_rule_baseline"]
    correlated = metrics["correlation_engine"]

    assert isolated["false_positive_alerts"] > 0  # the noise is real, not a no-op
    assert isolated["precision"] < 1.0  # isolated rules pay for that noise
    assert correlated["precision"] == 1.0  # correlation doesn't
    assert correlated["f1"] > isolated["f1"]


def test_correlation_reduces_alert_volume_versus_isolated_rules():
    metrics = run_evaluation(seed=42, scenarios_per_type=2)
    assert metrics["totals"]["incidents"] > 0
    assert metrics["totals"]["atomic_alerts"] > metrics["totals"]["incidents"]
    assert metrics["alert_reduction_ratio"] > 1.0


def test_scaling_scenarios_per_type_scales_the_dataset():
    small = run_evaluation(seed=1, scenarios_per_type=1)
    large = run_evaluation(seed=1, scenarios_per_type=3)
    assert large["totals"]["attack_scenarios"] == 3 * small["totals"]["attack_scenarios"]


def test_multi_seed_evaluation_reports_mean_and_spread():
    """Phase 9 #8: one seed is a sample, not a result."""
    report = run_multi_seed_evaluation(seeds=[10, 20, 30], scenarios_per_type=1)

    assert report["seeds"] == [10, 20, 30]
    assert set(report["per_seed"].keys()) == {"10", "20", "30"}

    recall = report["aggregated"]["correlation_engine.recall"]
    assert recall["n"] == 3
    assert 0.0 <= recall["mean"] <= 1.0
    assert recall["stdev"] >= 0.0
    assert recall["min"] <= recall["mean"] <= recall["max"]

    # each per-seed result is a full, real metrics dict, not a summary
    assert "totals" in report["per_seed"]["10"]


def test_multi_seed_evaluation_is_deterministic_per_seed():
    first = run_multi_seed_evaluation(seeds=[5, 6], scenarios_per_type=1)
    second = run_multi_seed_evaluation(seeds=[5, 6], scenarios_per_type=1)
    assert first == second
