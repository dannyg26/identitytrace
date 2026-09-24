"""scripts/report_workflow_semantics.py: the same two incidents scored as an
attack detector (benign twin = false positive) and as a risky-workflow
detector (benign twin = correct detection, intent unresolved)."""

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.db import Base
from tests.integration.test_correlation_bridged_pipeline import (
    OTHER_USER,
    USER,
    blocked,
    grants_consent,
    ingest,
    succeeds,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from report_workflow_semantics import summarize  # noqa: E402


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = Session(engine)
    yield session
    session.close()


def _two_chains(db):
    """Same workflow twice: 'attack' by USER, 'benign twin' by OTHER_USER."""
    ingest(db, [blocked("a-b", "18:17:49", USER), grants_consent("a-c", "18:18:21.2"), succeeds("a-s", "18:20:27", USER)])
    ingest(db, [blocked("t-b", "19:17:49", OTHER_USER), grants_consent("t-c", "19:18:21.5"),
                succeeds("t-s", "19:20:27", OTHER_USER)])
    return [
        {"label": "real_controlled_attack", "event_ids": ["a-b", "a-c", "a-s"]},
        {"label": "real_benign", "event_ids": ["t-b", "t-c", "t-s"]},
    ]


def test_attack_detector_view_counts_the_benign_twin_as_a_false_positive(db):
    report = summarize(db, _two_chains(db))

    assert report["A_attack_detector"] == {
        "true_positive_incidents": 1, "false_positive_incidents": 1, "precision": 0.5,
    }


def test_workflow_detector_view_counts_the_benign_twin_as_correct_and_leaves_intent_open(db):
    report = summarize(db, _two_chains(db))

    b = report["B_risky_workflow_detector"]
    assert (b["workflow_incidents"], b["workflow_confirmed_from_raw"], b["precision"]) == (2, 2, 1.0)
    assert "unresolved" in b["malicious_intent"]
    assert b["incidents_with_independent_escalation_evidence"] == 0


def test_both_incidents_are_identical_in_score_and_severity(db):
    """The whole point: nothing in the telemetry separates them."""
    rows = summarize(db, _two_chains(db))["incidents"]

    assert {(r["score"], r["severity"], r["escalated"]) for r in rows} == {(rows[0]["score"], rows[0]["severity"], False)}
    assert {r["attack_labelled"] for r in rows} == {True, False}
