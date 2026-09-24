"""End-to-end (raw Entra payload -> normalize -> detect -> correlate) tests
for IDT-CORR-006, using payloads shaped exactly like the real telemetry it
was validated on. The properties that only show up through the full
pipeline: order-independent arrival, a generic failure standing in for the
90094 block, and the benign lookalike pattern found in the real corpus.
"""

import itertools
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.correlation.loader import load_correlation_rules
from app.detections.loader import load_rules
from app.models.db import Base
from app.models.incident import IncidentRecord
from app.pipeline import normalize_payload, process_event

SP = "11111111-1111-4111-8111-111111111111"
OTHER_SP = "22222222-2222-4222-8222-222222222222"
GRAPH_RESOURCE_SP = "33333333-3333-4333-8333-333333333333"
USER = "idt-test-user3@example.test"
OTHER_USER = "idt-test-user2@example.test"
ADMIN = "idt-admin@example.test"
DAY = "2026-09-15T"


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = Session(engine)
    yield session
    session.close()


def signin(event_id, hhmmss, upn, error=0, sp=SP):
    return {"source": "entra", "raw": {
        "id": event_id, "createdDateTime": f"{DAY}{hhmmss}Z", "userPrincipalName": upn,
        "clientAppUsed": "Mobile Apps and Desktop clients", "servicePrincipalId": sp,
        "status": {"errorCode": error},
    }}


def blocked(event_id="blocked", hhmmss="18:17:49", upn=USER, sp=SP):
    return signin(event_id, hhmmss, upn, error=90094, sp=sp)


def succeeds(event_id="success", hhmmss="18:20:27", upn=USER, sp=SP):
    return signin(event_id, hhmmss, upn, error=0, sp=sp)


def grants_consent(event_id="consent", hhmmss="18:18:21.208964", admin=ADMIN, sp=SP,
                   scope=" openid profile Files.Read.All offline_access"):
    """Real shape of 'Add delegated permission grant' (see the normalizer
    tests for why targetResources[0] is deliberately NOT the client)."""
    return {"source": "entra", "raw": {
        "id": event_id, "category": "ApplicationManagement",
        "activityDateTime": f"{DAY}{hhmmss}Z",
        "activityDisplayName": "Add delegated permission grant",
        "initiatedBy": {"user": {"id": "admin-id", "userPrincipalName": admin}},
        "targetResources": [
            {"type": "ServicePrincipal", "id": GRAPH_RESOURCE_SP, "displayName": "Microsoft Graph",
             "modifiedProperties": [
                 {"displayName": "DelegatedPermissionGrant.Scope", "oldValue": '" openid"',
                  "newValue": json.dumps(scope)},
                 {"displayName": "ServicePrincipal.ObjectID", "oldValue": None,
                  "newValue": json.dumps(sp)},
             ]},
            {"type": "ServicePrincipal", "id": sp, "displayName": None, "modifiedProperties": []},
        ],
        "result": "success",
    }}


def ingest(db, payloads):
    rules, correlation_rules = load_rules(), load_correlation_rules()
    for payload in payloads:
        process_event(db, normalize_payload(payload), rules, correlation_rules)


def bridged_incidents(db):
    return db.query(IncidentRecord).filter(IncidentRecord.correlation_rule_id == "IDT-CORR-006").all()


# ---- positive ----

def test_real_sequence_correlates_into_one_incident_attributed_to_the_requesting_user(db):
    ingest(db, [blocked(), grants_consent(), succeeds()])

    (incident,) = bridged_incidents(db)
    assert incident.identity_id == USER  # not the admin
    assert incident.attack_chain == [
        "admin_consent_required", "risky_oauth_consent", "new_session_context",
    ]
    assert incident.evidence_ids == ["blocked", "consent", "success"]


def test_incident_shows_who_did_each_step_and_the_shared_entity(db):
    ingest(db, [blocked(), grants_consent(), succeeds()])

    (incident,) = bridged_incidents(db)
    reasons = incident.evidence_reasons
    assert [r["actor_id"] for r in reasons] == [USER, ADMIN, USER]
    assert {r["entity"] for r in reasons} == {SP}


@pytest.mark.parametrize("order", list(itertools.permutations(range(3))))
def test_arrival_order_does_not_matter(db, order):
    """Real: audit events propagated minutes before the matching sign-ins,
    and the logs come from different endpoints - whichever event of the
    chain arrives last must complete it."""
    events = [blocked(), grants_consent(), succeeds()]
    ingest(db, [events[i] for i in order])

    (incident,) = bridged_incidents(db)
    assert incident.incident_id == "IDT-CORR-006:blocked"


def test_replaying_the_chain_is_idempotent_and_preserves_triage(db):
    ingest(db, [blocked(), grants_consent(), succeeds()])
    (incident,) = bridged_incidents(db)
    incident.status, incident.analyst_disposition = "resolved", "true_positive"
    db.commit()

    ingest(db, [blocked(), grants_consent(), succeeds()])

    (again,) = bridged_incidents(db)
    assert again.incident_id == incident.incident_id
    assert (again.status, again.analyst_disposition) == ("resolved", "true_positive")


def test_the_existing_single_identity_rules_are_unaffected(db):
    ingest(db, [blocked(), grants_consent(), succeeds()])
    others = db.query(IncidentRecord).filter(IncidentRecord.correlation_rule_id != "IDT-CORR-006").all()
    assert others == []


# ---- negatives, through the full pipeline ----

def test_a_different_service_principal_on_the_consent_does_not_correlate(db):
    ingest(db, [blocked(), grants_consent(sp=OTHER_SP), succeeds()])
    assert bridged_incidents(db) == []


def test_a_different_service_principal_on_the_success_does_not_correlate(db):
    ingest(db, [blocked(), grants_consent(), succeeds(sp=OTHER_SP)])
    assert bridged_incidents(db) == []


def test_post_consent_success_by_a_different_user_does_not_correlate(db):
    ingest(db, [blocked(), grants_consent(), succeeds(upn=OTHER_USER)])
    assert bridged_incidents(db) == []


def test_admins_own_success_does_not_complete_the_requesters_chain(db):
    ingest(db, [blocked(), grants_consent(), succeeds(event_id="admin-success", upn=ADMIN)])
    assert bridged_incidents(db) == []


def test_consent_outside_the_window_does_not_correlate(db):
    ingest(db, [blocked(hhmmss="18:00:00"), grants_consent(hhmmss="18:15:01"), succeeds(hhmmss="18:16:00")])
    assert bridged_incidents(db) == []


def test_success_outside_the_window_does_not_correlate(db):
    ingest(db, [blocked(hhmmss="18:00:00"), grants_consent(hhmmss="18:01:00"), succeeds(hhmmss="18:15:01")])
    assert bridged_incidents(db) == []


def test_success_before_consent_does_not_correlate(db):
    ingest(db, [blocked(hhmmss="18:17:49"), succeeds(hhmmss="18:18:00"), grants_consent(hhmmss="18:18:21")])
    assert bridged_incidents(db) == []


def test_consent_before_the_block_does_not_correlate(db):
    ingest(db, [grants_consent(hhmmss="18:16:00"), blocked(hhmmss="18:17:49"), succeeds(hhmmss="18:20:27")])
    assert bridged_incidents(db) == []


def test_a_generic_failure_is_not_the_admin_consent_block(db):
    """errorCode 50199 ('user confirmation required') appears on both real
    benign and attack device-code sign-ins - it is not 90094."""
    ingest(db, [signin("generic-fail", "18:17:49", USER, error=50199), grants_consent(), succeeds()])
    assert bridged_incidents(db) == []


def test_a_failed_sign_in_after_consent_is_not_a_successful_one(db):
    ingest(db, [blocked(), grants_consent(), signin("retry-fail", "18:20:27", USER, error=50199)])
    assert bridged_incidents(db) == []


def test_consent_and_success_without_the_block_do_not_correlate(db):
    ingest(db, [grants_consent(), succeeds()])
    assert bridged_incidents(db) == []


def test_block_and_consent_without_a_success_do_not_correlate(db):
    ingest(db, [blocked(), grants_consent()])
    assert bridged_incidents(db) == []


def test_a_sign_in_with_a_nil_service_principal_cannot_complete_a_chain(db):
    """Real browser/portal sign-ins carry the all-zero placeholder GUID."""
    ingest(db, [blocked(), grants_consent(), succeeds(sp="00000000-0000-0000-0000-000000000000")])
    assert bridged_incidents(db) == []


def test_the_real_benign_lookalike_does_not_correlate(db):
    """Found in the real benign corpus: routine admin consent for this exact
    service principal, with several users signing in successfully within
    ~3-5 minutes - and no blocked sign-in anywhere. App + time alone would
    have joined these; the 90094 anchor is what keeps them apart."""
    ingest(db, [
        grants_consent(event_id="benign-consent", hhmmss="18:57:09.577578"),
        succeeds(event_id="u1", hhmmss="18:59:53", upn="idt-test-user1@example.test"),
        succeeds(event_id="u2", hhmmss="19:00:34", upn="idt-test-user2@example.test"),
        succeeds(event_id="u3", hhmmss="19:01:12", upn="idt-test-user3@example.test"),
        succeeds(event_id="adm", hhmmss="18:57:09", upn=ADMIN),
    ])
    assert bridged_incidents(db) == []
    assert db.query(IncidentRecord).count() == 0


def test_blocked_for_one_service_principal_then_consent_for_another_does_not_correlate(db):
    ingest(db, [blocked(sp=OTHER_SP), grants_consent(sp=SP), succeeds(sp=SP)])
    assert bridged_incidents(db) == []
