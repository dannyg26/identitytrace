"""Run the frozen holdout dataset (tests/fixtures/holdout/holdout_v1.json)
through the real pipeline and report metrics - Phase 9 #6.

Deliberately separate from app/evaluation/harness.py's run_evaluation():
that one *generates* a fresh dataset every call; this one *loads* a
static, checked-in file and never regenerates it. Mixing the two code
paths would defeat the point of freezing - a later change to the
generator must not be able to silently change what "the holdout result"
means.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.correlation.loader import load_correlation_rules
from app.detections.loader import load_rules
from app.evaluation.metrics import compute_metrics
from app.evaluation.scenarios import BenignSequence, GeneratedEvent, ScenarioInstance
from app.models.db import Base
from app.pipeline import normalize_payload, process_event

DEFAULT_HOLDOUT_PATH = (
    Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures" / "holdout" / "holdout_v1.json"
)


def _deserialize_event(raw: dict) -> GeneratedEvent:
    return GeneratedEvent(
        payload=raw["payload"],
        event_id=raw["event_id"],
        timestamp=datetime.fromisoformat(raw["timestamp"]),
        label=raw["label"],
        attack_id=raw.get("attack_id"),
        attack_type=raw.get("attack_type"),
    )


def load_holdout_dataset(path: Path = DEFAULT_HOLDOUT_PATH) -> tuple[list[BenignSequence], list[ScenarioInstance]]:
    data = json.loads(path.read_text(encoding="utf-8"))

    benign_sequences = [
        BenignSequence(
            sequence_id=s["sequence_id"], persona=s["persona"], identity=s["identity"],
            events=[_deserialize_event(e) for e in s["events"]],
        )
        for s in data["benign_sequences"]
    ]
    instances = [
        ScenarioInstance(
            scenario_id=i["scenario_id"], attack_type=i["attack_type"], identity=i["identity"],
            start_time=datetime.fromisoformat(i["start_time"]),
            events=[_deserialize_event(e) for e in i["events"]],
        )
        for i in data["attack_scenarios"]
    ]
    return benign_sequences, instances


def run_holdout_evaluation(path: Path = DEFAULT_HOLDOUT_PATH) -> dict:
    benign_sequences, instances = load_holdout_dataset(path)

    all_events = [e for seq in benign_sequences for e in seq.events]
    for instance in instances:
        all_events.extend(instance.events)
    all_events.sort(key=lambda e: e.timestamp)  # see harness.py's run_evaluation for why this matters

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

        return compute_metrics(
            db, instances, malicious_event_ids, benign_event_ids,
            benign_sequences=benign_sequences,
        )
    finally:
        db.close()
