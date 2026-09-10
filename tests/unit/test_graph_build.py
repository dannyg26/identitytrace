from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.graph.build import build_incident_graph
from app.models.db import Base
from app.models.event import EventRecord, NormalizedEvent


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = Session(engine)
    yield session
    session.close()


def _insert(db, event_id, **overrides):
    kwargs = dict(
        event_id=event_id,
        timestamp=datetime(2026, 9, 9, 9, 0, tzinfo=timezone.utc),
        source="entra",
        event_type="signin",
        action="login",
        result="success",
        actor_id="alice@example.test",
        actor_type="user",
    )
    kwargs.update(overrides)
    event = NormalizedEvent(**kwargs)
    db.add(EventRecord.from_schema(event))
    db.commit()


def _incident(evidence_ids, **overrides):
    kwargs = dict(
        incident_id="INC-1",
        identity_id="alice@example.test",
        correlation_rule_title="Test correlation",
        evidence_ids=evidence_ids,
    )
    kwargs.update(overrides)
    return kwargs


def test_identity_and_incident_nodes_always_present(db):
    _insert(db, "evt-1")
    graph = build_incident_graph(db, _incident(["evt-1"]))
    assert graph.nodes["identity:alice@example.test"]["kind"] == "identity"
    assert graph.nodes["incident:INC-1"]["kind"] == "incident"


def test_event_is_evidence_for_incident(db):
    _insert(db, "evt-1")
    graph = build_incident_graph(db, _incident(["evt-1"]))
    assert graph.has_node("event:evt-1")
    assert graph.has_edge("identity:alice@example.test", "event:evt-1")
    edge_data = graph.get_edge_data("identity:alice@example.test", "event:evt-1")
    assert any(d["relation"] == "TRIGGERED" for d in edge_data.values())
    incident_edge = graph.get_edge_data("event:evt-1", "incident:INC-1")
    assert any(d["relation"] == "EVIDENCE_FOR" for d in incident_edge.values())


def test_session_ip_device_chain(db):
    _insert(
        db, "evt-1",
        session_id="sess-1", ip_address="1.1.1.1", device_id="dev-1",
    )
    graph = build_incident_graph(db, _incident(["evt-1"]))

    assert graph.has_node("session:sess-1")
    assert graph.has_node("ip:1.1.1.1")
    assert graph.has_node("device:dev-1")

    auth_edge = graph.get_edge_data("identity:alice@example.test", "session:sess-1")
    assert any(d["relation"] == "AUTHENTICATED_VIA" for d in auth_edge.values())

    from_edge = graph.get_edge_data("session:sess-1", "ip:1.1.1.1")
    assert any(d["relation"] == "FROM" for d in from_edge.values())

    on_edge = graph.get_edge_data("session:sess-1", "device:dev-1")
    assert any(d["relation"] == "ON" for d in on_edge.values())


def test_ip_and_device_anchor_directly_on_event_without_a_session(db):
    _insert(db, "evt-1", ip_address="2.2.2.2", device_id="dev-2")
    graph = build_incident_graph(db, _incident(["evt-1"]))

    assert not graph.has_node("session:None")
    from_edge = graph.get_edge_data("event:evt-1", "ip:2.2.2.2")
    assert any(d["relation"] == "FROM" for d in from_edge.values())


def test_oauth_consent_creates_app_and_permission_nodes(db):
    _insert(
        db, "evt-1",
        event_type="oauth_consent", action="grant_permission",
        app_id="app-1", resource_id="EvilApp", permissions=["Files.Read.All", "offline_access"],
    )
    graph = build_incident_graph(db, _incident(["evt-1"]))

    assert graph.has_node("app:app-1")
    assert graph.nodes["app:app-1"]["label"] == "EvilApp"  # display name, not raw app_id
    consent_edge = graph.get_edge_data("identity:alice@example.test", "app:app-1")
    assert any(d["relation"] == "CONSENTED_TO" for d in consent_edge.values())

    for perm in ("Files.Read.All", "offline_access"):
        assert graph.has_node(f"permission:{perm}")
        grant_edge = graph.get_edge_data("app:app-1", f"permission:{perm}")
        assert any(d["relation"] == "GRANTED" for d in grant_edge.values())


def test_resource_access_creates_accessed_edge(db):
    _insert(db, "evt-1", event_type="repo_clone", action="clone", resource_id="acme/secret-repo")
    graph = build_incident_graph(db, _incident(["evt-1"]))

    assert graph.has_node("resource:acme/secret-repo")
    edge = graph.get_edge_data("identity:alice@example.test", "resource:acme/secret-repo")
    assert any(d["relation"] == "ACCESSED" for d in edge.values())


def test_role_action_creates_privilege_node(db):
    _insert(db, "evt-1", event_type="audit", action="Add member to role")
    graph = build_incident_graph(db, _incident(["evt-1"]))

    assert graph.has_node("privilege:Add member to role")
    edge = graph.get_edge_data("identity:alice@example.test", "privilege:Add member to role")
    assert any(d["relation"] == "ASSIGNED" for d in edge.values())


def test_missing_event_is_skipped_gracefully(db):
    # evidence_ids references an event that isn't in the DB - shouldn't crash.
    graph = build_incident_graph(db, _incident(["does-not-exist"]))
    assert graph.has_node("identity:alice@example.test")
    assert graph.has_node("incident:INC-1")
    assert not graph.has_node("event:does-not-exist")


def test_multiple_events_all_link_to_the_same_incident(db):
    _insert(db, "evt-1")
    _insert(db, "evt-2", event_type="oauth_consent", action="grant", app_id="app-1")
    graph = build_incident_graph(db, _incident(["evt-1", "evt-2"]))

    for eid in ("evt-1", "evt-2"):
        edge = graph.get_edge_data(f"event:{eid}", "incident:INC-1")
        assert any(d["relation"] == "EVIDENCE_FOR" for d in edge.values())
