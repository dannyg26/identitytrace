"""Reproducible evaluation harness (blueprint §10, extended by Phase 9).

Generates a labeled benign+attack dataset with a fixed seed, runs every
event through app.pipeline.process_event - the exact same code path the
live app uses - against a throwaway in-memory database, then reports
precision/recall/F1/false-positive-rate/latency/alert-reduction comparing
the correlation engine against an isolated-rule baseline.

Running an evaluation can never touch the live database: a fresh SQLite
in-memory engine is created for each call and discarded afterward.
"""

from __future__ import annotations

import random
import statistics
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.correlation.loader import load_correlation_rules
from app.detections.loader import load_rules
from app.evaluation import scenarios as scen
from app.evaluation.metrics import compute_metrics
from app.models.db import Base
from app.pipeline import normalize_payload, process_event

DEFAULT_BASE_TIME = datetime(2026, 9, 1, tzinfo=timezone.utc)


def run_evaluation(
    seed: int = 42,
    scenarios_per_type: int = 2,
    num_benign_identities: int = 5,
    base_time: datetime = DEFAULT_BASE_TIME,
) -> dict:
    rng = random.Random(seed)

    benign_sequences = scen.generate_benign_population(
        rng, base_time, num_identities=num_benign_identities
    )
    benign_sequences += scen.generate_benign_edge_cases(rng, base_time)
    benign_sequences += scen.generate_ambiguous_singletons(rng, base_time)
    instances = scen.generate_attack_scenarios(rng, base_time, instances_per_type=scenarios_per_type)

    all_events = [e for seq in benign_sequences for e in seq.events]
    for instance in instances:
        all_events.extend(instance.events)
    # Chronological order matters: build_profile/correlation both query by
    # timestamp, and a row only exists once it's actually been inserted -
    # processing out of order would make an "earlier" event's baseline
    # miss history it should have seen.
    all_events.sort(key=lambda e: e.timestamp)

    malicious_event_ids = {
        e.event_id for instance in instances for e in instance.events if e.label == "malicious"
    }
    benign_event_ids = {e.event_id for e in all_events if e.label == "benign"}

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = Session(engine)

    rules = load_rules()
    correlation_rules = load_correlation_rules()

    try:
        for generated in all_events:
            event = normalize_payload(generated.payload)
            process_event(db, event, rules, correlation_rules)

        metrics = compute_metrics(
            db, instances, malicious_event_ids, benign_event_ids,
            benign_sequences=benign_sequences,
        )
    finally:
        db.close()

    return metrics


# Metric paths (dot-separated) averaged/stdev'd across seeds by
# run_multi_seed_evaluation. Kept explicit rather than walking the whole
# dict blindly, since not every value is numeric (scenario_coverage and
# per_scenario are structural, not something "mean ± stdev" means anything
# for).
_MULTI_SEED_METRIC_PATHS = [
    "isolated_rule_baseline.recall",
    "isolated_rule_baseline.precision",
    "isolated_rule_baseline.f1",
    "isolated_rule_baseline.false_positive_rate",
    "isolated_rule_baseline.avg_detection_latency_seconds",
    "correlation_engine.recall",
    "correlation_engine.precision",
    "correlation_engine.f1",
    "correlation_engine.false_positive_rate",
    "correlation_engine.avg_detection_latency_seconds",
    "alert_reduction_ratio",
]


def _get_path(d: dict, path: str):
    value = d
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
        if value is None:
            return None
    return value


def run_multi_seed_evaluation(
    seeds: list[int],
    scenarios_per_type: int = 2,
    num_benign_identities: int = 5,
    base_time: datetime = DEFAULT_BASE_TIME,
) -> dict:
    """Phase 9 #8: one seed is one sample, not a result. Runs the full
    harness once per seed and reports mean ± stdev for every scalar
    metric, plus every individual run for transparency (never hide the
    spread behind an aggregate)."""
    per_seed_results = {seed: run_evaluation(seed, scenarios_per_type, num_benign_identities, base_time) for seed in seeds}

    aggregated: dict[str, dict] = {}
    for path in _MULTI_SEED_METRIC_PATHS:
        values = [v for r in per_seed_results.values() if (v := _get_path(r, path)) is not None]
        if not values:
            continue
        aggregated[path] = {
            "mean": round(statistics.mean(values), 4),
            "stdev": round(statistics.stdev(values), 4) if len(values) > 1 else 0.0,
            "min": round(min(values), 4),
            "max": round(max(values), 4),
            "n": len(values),
        }

    return {
        "seeds": seeds,
        "aggregated": aggregated,
        "per_seed": {str(seed): result for seed, result in per_seed_results.items()},
    }
