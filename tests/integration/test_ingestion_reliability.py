"""Regression checks for retry safety, late delivery, and atomic persistence."""

from itertools import permutations

import pytest

from app import pipeline
from app.models.db import SessionLocal
from app.models.event import EventRecord


def _chain():
    common = {
        "source": "entra", "result": "success", "actor_id": "alice@example.test",
        "actor_type": "user",
    }
    return [
        dict(common, event_id="a", timestamp="2026-01-01T09:00:00Z",
             event_type="signin", action="login", auth_protocol="deviceCode"),
        dict(common, event_id="b", timestamp="2026-01-01T09:05:00Z",
             event_type="oauth_consent", action="consent", permissions=["Files.Read.All"]),
        dict(common, event_id="c", timestamp="2026-01-01T09:10:00Z",
             event_type="file_access", action="read", resource_type="mailbox"),
    ]


@pytest.mark.parametrize("order", list(permutations(range(3))))
def test_atomic_signal_chain_detected_in_every_delivery_order(client, order):
    events = _chain()
    for index in order:
        assert client.post("/api/events", json=events[index]).status_code == 201
    incidents = client.get("/api/incidents").json()
    assert len(incidents) == 1
    assert incidents[0]["evidence_ids"] == ["a", "b", "c"]
    assert incidents[0]["score"] == 100


def test_late_middle_event_does_not_join_a_chain_exceeding_window(client):
    events = _chain()
    events[2]["timestamp"] = "2026-01-01T09:20:00Z"
    for index in (0, 2, 1):
        assert client.post("/api/events", json=events[index]).status_code == 201
    assert client.get("/api/incidents").json() == []


@pytest.mark.parametrize("last_timestamp, expected", [
    ("2026-01-01T09:15:00Z", 1), ("2026-01-01T09:15:01Z", 0),
])
def test_late_delivery_respects_exact_window_boundary(client, last_timestamp, expected):
    events = _chain()
    events[2]["timestamp"] = last_timestamp
    for index in (2, 1, 0):
        assert client.post("/api/events", json=events[index]).status_code == 201
    assert len(client.get("/api/incidents").json()) == expected


@pytest.mark.parametrize("change", [
    {"permissions": []}, {"actor_id": "other@example.test"}, {"source": "github"},
    {"timestamp": "2026-01-02T09:05:00Z"}, {"raw_event_ref": {"changed": True}},
])
def test_conflicting_event_id_cannot_replace_evidence(client, change):
    events = _chain()
    for event in events:
        client.post("/api/events", json=event)
    original = client.get("/api/events/b").json()
    matches = client.get("/api/events/b/matches").json()
    incidents = client.get("/api/incidents").json()
    response = client.post("/api/events", json={**events[1], **change})
    assert response.status_code == 409
    assert client.get("/api/events/b").json() == original
    assert client.get("/api/events/b/matches").json() == matches
    assert client.get("/api/incidents").json() == incidents


def test_identical_retry_accepts_equivalent_timezone_and_preserves_triage(client):
    events = _chain()
    for event in events:
        client.post("/api/events", json=event)
    incident_id = client.get("/api/incidents").json()[0]["incident_id"]
    client.patch(f"/api/incidents/{incident_id}", json={"status": "resolved", "notes": "reviewed"})
    before = client.get(f"/api/incidents/{incident_id}").json()
    replay = {**events[1], "timestamp": "2026-01-01T04:05:00-05:00"}
    assert client.post("/api/events", json=replay).status_code == 201
    assert client.get(f"/api/incidents/{incident_id}").json() == before
    assert len(client.get("/api/events").json()) == 3


def test_new_event_recorrelation_preserves_existing_triage(client):
    events = _chain()
    for event in events:
        client.post("/api/events", json=event)
    incident_id = client.get("/api/incidents").json()[0]["incident_id"]
    client.patch(f"/api/incidents/{incident_id}", json={
        "status": "resolved", "analyst_disposition": "benign", "notes": "reviewed",
    })
    later = {**events[2], "event_id": "d", "timestamp": "2026-01-01T09:11:00Z"}
    assert client.post("/api/events", json=later).status_code == 201
    incidents = client.get("/api/incidents").json()
    assert len(incidents) == 1
    assert incidents[0]["status"] == "resolved"
    assert incidents[0]["analyst_disposition"] == "benign"
    assert incidents[0]["notes"] == "reviewed"


def test_correlation_failure_rolls_back_event_and_signals(client, monkeypatch):
    original = pipeline.run_correlation_for_actor

    def fail(*args, **kwargs):
        raise RuntimeError("simulated correlation failure")

    monkeypatch.setattr(pipeline, "run_correlation_for_actor", fail)
    with pytest.raises(RuntimeError, match="simulated correlation failure"):
        client.post("/api/events", json=_chain()[0])
    with SessionLocal() as db:
        assert db.get(EventRecord, "a") is None
    assert client.get("/api/matches").json() == []
    monkeypatch.setattr(pipeline, "run_correlation_for_actor", original)
    assert client.post("/api/events", json=_chain()[0]).status_code == 201


def test_incident_write_failure_rolls_back_entire_completion(client, monkeypatch):
    events = _chain()
    for event in events[:2]:
        client.post("/api/events", json=event)
    original = pipeline.upsert_incident

    def fail_after_write(db, payload):
        original(db, payload)
        db.flush()
        raise RuntimeError("simulated incident persistence failure")

    monkeypatch.setattr(pipeline, "upsert_incident", fail_after_write)
    with pytest.raises(RuntimeError, match="simulated incident persistence failure"):
        client.post("/api/events", json=events[2])
    assert client.get("/api/events/c").status_code == 404
    assert client.get("/api/incidents").json() == []
    assert all(match["event_id"] != "c" for match in client.get("/api/matches").json())
    monkeypatch.setattr(pipeline, "upsert_incident", original)
    assert client.post("/api/events", json=events[2]).status_code == 201
    assert len(client.get("/api/incidents").json()) == 1


def test_invalid_normalized_event_returns_validation_error(client):
    assert client.post("/api/events", json={"source": "entra"}).status_code == 422


@pytest.mark.parametrize("payload", [
    {"scenarios_per_type": 0}, {"scenarios_per_type": 11},
    {"num_benign_identities": -1}, {"num_benign_identities": 21},
])
def test_evaluation_api_rejects_unbounded_workloads(client, payload):
    assert client.post("/api/evaluation/run", json=payload).status_code == 422


@pytest.mark.parametrize("count", [-1, 0, 11, 1000000])
def test_evaluation_dashboard_rejects_unbounded_workloads(client, count):
    assert client.get("/evaluation", params={"scenarios_per_type": count}).status_code == 422
