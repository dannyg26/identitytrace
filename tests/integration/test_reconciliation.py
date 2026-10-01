import pytest

from app.baselines.profile import build_profile
from app.models.db import SessionLocal
from app.models.operations import BaselineState
from tests.integration.test_ingestion_reliability import _chain


def _baseline_chain():
    common = dict(source="entra", event_type="signin", action="login", result="success",
                  actor_id="alice", actor_type="user", auth_protocol="interactive",
                  mfa_result="success", ip_address="192.0.2.1")
    history = [dict(common, event_id=f"history-{i}", timestamp=f"2026-01-01T08:0{i}:00Z") for i in range(3)]
    weak = dict(common, event_id="weak", timestamp="2026-01-01T09:00:00Z",
                mfa_result="not_present", ip_address="192.0.2.2")
    bulk = dict(common, event_id="bulk", timestamp="2026-01-01T09:05:00Z",
                event_type="download", action="read", bytes_transferred=500000000)
    return history + [weak, bulk]


@pytest.mark.parametrize("order", [range(5), range(4, -1, -1), [3, 4, 2, 0, 1]])
def test_late_history_rebuilds_baseline_dependent_chains(client, order):
    events = _baseline_chain()
    for index in order:
        assert client.post("/api/events", json=events[index]).status_code == 201
    incidents = client.get("/api/incidents").json()
    assert any(i["correlation_rule_id"] == "IDT-CORR-004" for i in incidents)
    deviations = client.get("/api/events/weak/deviations").json()
    assert "new_ip" in {d["deviation_type"] for d in deviations}
    with SessionLocal() as db:
        cached = db.get(BaselineState, "alice").profile
        rebuilt = build_profile(db, "alice").model_dump(mode="json")
        # JSON set serialization has no ordering contract.
        for key in cached:
            if isinstance(cached[key], list):
                assert set(cached[key]) == set(rebuilt[key])
            else:
                assert cached[key] == rebuilt[key]


def test_late_known_ip_supersedes_finding_without_erasing_notes(client):
    for event in _baseline_chain():
        client.post("/api/events", json=event)
    incident = next(i for i in client.get("/api/incidents").json() if i["correlation_rule_id"] == "IDT-CORR-004")
    client.patch(f'/api/incidents/{incident["incident_id"]}', json={"notes": "investigated", "status": "resolved"})
    late = {**_baseline_chain()[0], "event_id": "late-known-ip", "timestamp": "2026-01-01T08:30:00Z", "ip_address": "192.0.2.2"}
    assert client.post("/api/events", json=late).status_code == 201
    assert not any(i["incident_id"] == incident["incident_id"] for i in client.get("/api/incidents").json())
    archived = client.get(f'/api/incidents/{incident["incident_id"]}').json()
    assert archived["superseded_at"]
    assert archived["notes"] == "investigated"
    assert archived["status"] == "resolved"
    assert client.get("/api/audit").json()[0]["action"] == "incident.superseded"
    assert "new_ip" not in {d["deviation_type"] for d in client.get("/api/events/weak/deviations").json()}


def test_explicit_cross_source_link_reconciles_existing_events(client):
    events = _chain()
    events[2]["source"] = "github"
    events[2]["actor_id"] = "alice-dev"
    for event in events:
        client.post("/api/events", json=event)
    assert client.get("/api/incidents").json() == []
    link = {"source": "github", "alias": "alice-dev", "canonical_id": "alice@example.test"}
    assert client.post("/api/identity-links", json=link).status_code == 201
    assert len(client.get("/api/incidents").json()) == 1
    stored = client.get("/api/events/c").json()
    assert stored["actor_id"] == "alice@example.test"
    assert stored["source_actor_id"] == "alice-dev"
    assert client.post("/api/events", json=events[2]).status_code == 201
    assert client.post("/api/identity-links", json=link).status_code == 201
    assert client.post("/api/identity-links", json={**link, "canonical_id": "other"}).status_code == 409
    assert client.get("/api/identity-links").json() == [link]
    assert client.get("/api/audit").json()[0]["action"] == "identity.linked"


@pytest.mark.parametrize("change", [{"source": "unknown"}, {"alias": " "}, {"canonical_id": ""}])
def test_invalid_links_rejected(client, change):
    assert client.post("/api/identity-links", json={"source": "github", "alias": "a", "canonical_id": "alice", **change}).status_code == 422
