from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.evaluation.metrics import compute_metrics
from app.evaluation.scenarios import GeneratedEvent, ScenarioInstance
from app.models.db import Base
from app.models.detection import DetectionMatchRecord
from app.models.incident import IncidentRecord


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = Session(engine)
    yield session
    session.close()


def _match(db, event_id, actor_id="alice", ts=None):
    db.add(DetectionMatchRecord(
        match_id=f"{event_id}:rule", rule_id="RULE-1", event_id=event_id, actor_id=actor_id,
        timestamp=ts or datetime(2026, 1, 1, tzinfo=timezone.utc), title="t", severity="low",
        score=10, scenario=None, signal="sig", attack=[], reasons=["because"],
    ))
    db.commit()


def _incident(db, incident_id, evidence_ids, actor_id="alice", last_event_at=None):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    db.add(IncidentRecord(
        incident_id=incident_id, identity_id=actor_id, severity="high", score=80,
        confidence=0.9, attack_chain=["a", "b"], evidence_ids=evidence_ids,
        attack_mapping=[], correlation_rule_id="CORR-1", correlation_rule_title="t",
        scenario=None, window_seconds=600, first_event_at=now,
        last_event_at=last_event_at or now, score_breakdown={}, confidence_breakdown={},
        evidence_reasons=[], status="open", analyst_disposition=None, notes=None,
        created_at=now, updated_at=now,
    ))
    db.commit()


def _scenario(scenario_id, attack_type, malicious_ids, start_time=None) -> ScenarioInstance:
    start = start_time or datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        GeneratedEvent(payload={}, event_id=eid, timestamp=start, label="malicious",
                        attack_id=scenario_id, attack_type=attack_type)
        for eid in malicious_ids
    ]
    return ScenarioInstance(scenario_id, attack_type, "alice", start, events)


def test_recall_when_scenario_is_fully_detected(db):
    _match(db, "evt-1")
    _incident(db, "INC-1", ["evt-1"])
    scenario = _scenario("S1", "A1", {"evt-1"})

    metrics = compute_metrics(db, [scenario], malicious_event_ids={"evt-1"}, benign_event_ids=set())

    assert metrics["isolated_rule_baseline"]["recall"] == 1.0
    assert metrics["correlation_engine"]["recall"] == 1.0
    assert metrics["per_scenario"][0]["detected_isolated_rule"] is True
    assert metrics["per_scenario"][0]["detected_correlation"] is True


def test_recall_zero_when_nothing_fires(db):
    scenario = _scenario("S1", "A1", {"evt-1"})
    metrics = compute_metrics(db, [scenario], malicious_event_ids={"evt-1"}, benign_event_ids=set())

    assert metrics["isolated_rule_baseline"]["recall"] == 0.0
    assert metrics["correlation_engine"]["recall"] == 0.0


def test_isolated_detection_without_correlation_counts_only_for_isolated(db):
    # A match fires on the malicious event, but no incident ever forms
    # (e.g. the scenario is a standalone signal with no correlation rule -
    # exactly A6's designed gap).
    _match(db, "evt-1")
    scenario = _scenario("S1", "A6", {"evt-1"})
    metrics = compute_metrics(db, [scenario], malicious_event_ids={"evt-1"}, benign_event_ids=set())

    assert metrics["isolated_rule_baseline"]["recall"] == 1.0
    assert metrics["correlation_engine"]["recall"] == 0.0


def test_false_positive_alert_and_incident_on_benign_events(db):
    _match(db, "evt-benign")
    _incident(db, "INC-fp", ["evt-benign"])
    scenario = _scenario("S1", "A1", {"evt-mal"})

    metrics = compute_metrics(
        db, [scenario], malicious_event_ids={"evt-mal"}, benign_event_ids={"evt-benign"},
    )

    assert metrics["isolated_rule_baseline"]["false_positive_alerts"] == 1
    assert metrics["isolated_rule_baseline"]["false_positive_rate"] == 1.0  # 1 of 1 benign event
    assert metrics["correlation_engine"]["false_positive_incidents"] == 1
    # neither the FP alert nor the FP incident counts as a true positive
    assert metrics["isolated_rule_baseline"]["precision"] == 0.0
    assert metrics["correlation_engine"]["precision"] == 0.0


def test_precision_excludes_false_positives_from_numerator(db):
    _match(db, "evt-mal")
    _match(db, "evt-benign")
    _incident(db, "INC-1", ["evt-mal"])
    scenario = _scenario("S1", "A1", {"evt-mal"})

    metrics = compute_metrics(
        db, [scenario], malicious_event_ids={"evt-mal"}, benign_event_ids={"evt-benign"},
    )

    assert metrics["isolated_rule_baseline"]["precision"] == 0.5  # 1 tp / 2 total alerts
    assert metrics["correlation_engine"]["precision"] == 1.0  # 1 tp incident / 1 total incident


def test_alert_reduction_ratio(db):
    for i in range(6):
        _match(db, f"evt-{i}")
    _incident(db, "INC-1", ["evt-0", "evt-1", "evt-2"])
    _incident(db, "INC-2", ["evt-3", "evt-4", "evt-5"])
    scenario = _scenario("S1", "A1", {"evt-0"})

    metrics = compute_metrics(db, [scenario], malicious_event_ids={"evt-0"}, benign_event_ids=set())
    assert metrics["alert_reduction_ratio"] == 3.0  # 6 alerts / 2 incidents


def test_alert_reduction_ratio_is_none_with_no_incidents(db):
    scenario = _scenario("S1", "A1", {"evt-0"})
    metrics = compute_metrics(db, [scenario], malicious_event_ids={"evt-0"}, benign_event_ids=set())
    assert metrics["alert_reduction_ratio"] is None


def test_detection_latency_measured_from_scenario_start(db):
    start = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    alert_time = datetime(2026, 1, 1, 9, 2, tzinfo=timezone.utc)  # +120s
    incident_time = datetime(2026, 1, 1, 9, 5, tzinfo=timezone.utc)  # +300s
    _match(db, "evt-1", ts=alert_time)
    _incident(db, "INC-1", ["evt-1"], last_event_at=incident_time)
    scenario = _scenario("S1", "A1", {"evt-1"}, start_time=start)

    metrics = compute_metrics(db, [scenario], malicious_event_ids={"evt-1"}, benign_event_ids=set())

    assert metrics["isolated_rule_baseline"]["avg_detection_latency_seconds"] == 120.0
    assert metrics["correlation_engine"]["avg_detection_latency_seconds"] == 300.0


def test_scenario_coverage_grouped_by_attack_type(db):
    _match(db, "evt-a1")
    _match(db, "evt-a2")
    scenario_a1 = _scenario("S-A1", "A1", {"evt-a1"})
    scenario_a2 = _scenario("S-A2", "A2", {"evt-a2"})

    metrics = compute_metrics(
        db, [scenario_a1, scenario_a2],
        malicious_event_ids={"evt-a1", "evt-a2"}, benign_event_ids=set(),
    )

    assert metrics["scenario_coverage"]["A1"]["instances"] == 1
    assert metrics["scenario_coverage"]["A1"]["recall_isolated"] == 1.0
    assert metrics["scenario_coverage"]["A2"]["recall_isolated"] == 1.0
