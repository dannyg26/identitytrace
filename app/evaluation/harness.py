"""Reproducible evaluation harness (blueprint §10).

Generates a labeled benign+attack dataset with a fixed seed, runs every
event through app.pipeline.process_event - the exact same code path the
live app uses - against a throwaway in-memory database, then reports
precision/recall/false-positive-rate/latency/alert-reduction comparing the
correlation engine against an isolated-rule baseline.

Running an evaluation can never touch the live database: a fresh SQLite
in-memory engine is created for each call and discarded afterward.
"""

from __future__ import annotations

import random
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

    generated_benign = scen.generate_benign_population(
        rng, base_time, num_identities=num_benign_identities
    )
    generated_edge_cases = scen.generate_benign_edge_cases(rng, base_time)
    instances = scen.generate_attack_scenarios(rng, base_time, instances_per_type=scenarios_per_type)

    all_events = list(generated_benign) + list(generated_edge_cases)
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

        metrics = compute_metrics(db, instances, malicious_event_ids, benign_event_ids)
    finally:
        db.close()

    return metrics
