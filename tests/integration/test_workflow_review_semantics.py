"""IDT-CORR-006 as a HIGH-RISK WORKFLOW requiring analyst review, not an
attack detection (docs/evaluation.md, "A2 Benign Twin - Detection vs
Intent"): the 3-step correlation still matches exactly as before, scoring
uses only the scopes the grant ADDED, and severity is capped unless
independent baseline-deviation evidence exists.

Payloads mirror the two real chains: the attack (Mail.Read added to a grant
that already held offline_access) and its benign twin (Mail.ReadWrite added
likewise).
"""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.correlation.loader import load_correlation_rules
from app.models.baseline import BaselineDeviationRecord
from app.models.db import Base
from tests.integration.test_correlation_bridged_pipeline import (
    ADMIN,
    DAY,
    GRAPH_RESOURCE_SP,
    SP,
    USER,
    bridged_incidents,
    ingest,
    succeeds,
)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = Session(engine)
    yield session
    session.close()

# What the real tenant's grant looked like BEFORE either A2 chain: the Graph
# grant already carried these, so they were not granted by the chain's event.
PRIOR_SCOPE = " openid profile User.Read offline_access"


def cumulative_grant(added, event_id="consent", prior=PRIOR_SCOPE, hhmmss="18:18:21.208964"):
    """'Add delegated permission grant' whose newValue is the CUMULATIVE
    scope (prior + added), exactly the shape found in the real audit logs."""
    return {"source": "entra", "raw": {
        "id": event_id, "category": "ApplicationManagement",
        "activityDateTime": f"{DAY}{hhmmss}Z",
        "activityDisplayName": "Add delegated permission grant",
        "initiatedBy": {"user": {"id": "admin-id", "userPrincipalName": ADMIN}},
        "targetResources": [
            {"type": "ServicePrincipal", "id": GRAPH_RESOURCE_SP, "displayName": "Microsoft Graph",
             "modifiedProperties": [
                 {"displayName": "DelegatedPermissionGrant.Scope",
                  "oldValue": json.dumps(prior), "newValue": json.dumps(prior + " " + added)},
                 {"displayName": "ServicePrincipal.ObjectID", "oldValue": None,
                  "newValue": json.dumps(SP)},
             ]},
            {"type": "ServicePrincipal", "id": SP, "displayName": None, "modifiedProperties": []},
        ],
        "result": "success",
    }}


def blocked_at(event_id="blocked", hhmmss="18:17:49", **extra):
    return {"source": "entra", "raw": {
        "id": event_id, "createdDateTime": f"{DAY}{hhmmss}Z", "userPrincipalName": USER,
        "clientAppUsed": "Mobile Apps and Desktop clients", "servicePrincipalId": SP,
        "status": {"errorCode": 90094}, **extra,
    }}


def success_with(event_id="success", hhmmss="18:20:27", **extra):
    payload = succeeds(event_id=event_id, hhmmss=hhmmss)
    payload["raw"].update(extra)
    return payload


def history(n=4):
    """Prior ordinary sign-ins so the identity has a baseline (US, one device)."""
    return [
        {"source": "entra", "raw": {
            "id": f"hist-{i}", "createdDateTime": f"2026-09-1{i}T10:00:00Z", "userPrincipalName": USER,
            "clientAppUsed": "Browser", "appId": "app-usual", "ipAddress": "203.0.113.5",
            "location": {"countryOrRegion": "US"}, "deviceDetail": {"deviceId": "dev-1"},
            "status": {"errorCode": 0},
        }}
        for i in range(n)
    ]


# ---- 1. reclassification: same correlation, new meaning ----

def test_the_three_step_correlation_is_unchanged():
    rule = next(r for r in load_correlation_rules() if r.id == "IDT-CORR-006")

    assert rule.sequence == ["admin_consent_required", "risky_oauth_consent", "new_session_context"]
    assert rule.actor_binding == ["anchor", "any", "anchor"]
    assert rule.entity_field == "service_principal_id"
    assert rule.window_seconds == 900
    assert rule.score_bonus == 10  # not tuned


def test_the_rule_is_declared_a_workflow_review_not_an_attack_chain():
    rule = next(r for r in load_correlation_rules() if r.id == "IDT-CORR-006")

    assert rule.classification == "workflow_review"
    assert rule.severity_cap == "high"
    assert "compromise" not in rule.title.lower()
    assert "review" in rule.title.lower()


def test_the_chain_still_fires_for_both_the_attack_and_the_twin_shapes(db):
    ingest(db, [blocked_at(), cumulative_grant("Mail.Read"), success_with()])
    (attack,) = bridged_incidents(db)
    ingest(db, [
        blocked_at("b2", "19:17:49"), cumulative_grant("Mail.ReadWrite", event_id="c2", hhmmss="19:18:21.5"),
        success_with("s2", "19:20:27"),
    ])

    assert len(bridged_incidents(db)) == 2
    assert attack.classification == "workflow_review"


# ---- 2. scoring uses only the scopes this grant added ----

def test_only_the_added_scope_reaches_the_detection_engine(db):
    from app.pipeline import normalize_payload

    event = normalize_payload(cumulative_grant("Mail.Read"))

    assert event.permissions == ["Mail.Read"]


@pytest.mark.parametrize("added", ["Mail.Read", "Mail.ReadWrite"])
def test_prior_offline_access_no_longer_inflates_the_chain(db, added):
    """Before the fix both real chains scored 85/critical: IDT-ENTRA-002
    (weight 45) fired on offline_access granted in an EARLIER event. On the
    delta only IDT-ENTRA-001 (35) fires: 15 + 35 + 15 + 10 = 75."""
    ingest(db, [blocked_at(), cumulative_grant(added), success_with()])

    (incident,) = bridged_incidents(db)
    assert incident.score_breakdown["event_risk"] == 65
    assert incident.score == 75
    assert incident.severity == "high"
    consent_signal = next(r for r in incident.evidence_reasons if r["signal_type"] == "risky_oauth_consent")
    assert consent_signal["weight"] == 35


def test_genuinely_added_offline_access_is_still_scored(db):
    """The fix removes inflation, not the signal: a grant that really adds
    offline_access still fires IDT-ENTRA-002."""
    ingest(db, [blocked_at(), cumulative_grant("offline_access Mail.Read", prior=" openid profile"), success_with()])

    (incident,) = bridged_incidents(db)
    consent_signal = next(r for r in incident.evidence_reasons if r["signal_type"] == "risky_oauth_consent")
    assert consent_signal["weight"] == 45


# ---- 3. detection separated from escalation ----

def test_without_independent_evidence_severity_is_capped_below_critical(db):
    """A genuine offline_access + risky scope grant reaches 85 on chain
    signals alone (45+15+15+10). Nothing independent says it is malicious,
    so it is capped at high and the cap is recorded."""
    ingest(db, [
        blocked_at(), cumulative_grant("offline_access Mail.Read", prior=" openid profile"), success_with(),
    ])

    (incident,) = bridged_incidents(db)
    assert incident.severity == "high"
    assert incident.score == 84
    assert incident.score_breakdown["uncapped_score"] == 85
    assert incident.escalation["cap_applied"] is True
    assert incident.escalation["escalated"] is False
    assert incident.escalation["evidence"] == []


def test_a_new_country_on_the_chain_is_independent_evidence_and_escalates(db):
    ingest(db, history() + [
        blocked_at(location={"countryOrRegion": "US"}, deviceDetail={"deviceId": "dev-1"}),
        cumulative_grant("Mail.Read"),
        success_with(location={"countryOrRegion": "RO"}, deviceDetail={"deviceId": "dev-1"}),
    ])

    (incident,) = bridged_incidents(db)
    assert incident.escalation["escalated"] is True
    assert [e["deviation_type"] for e in incident.escalation["evidence"]] == ["new_country"]
    assert incident.score_breakdown["behavioral_deviation"] == 20
    assert incident.score == 65 + 20 + 10
    assert incident.severity == "critical"
    assert incident.escalation["cap_applied"] is False


def test_a_new_device_on_the_chain_is_independent_evidence_and_escalates(db):
    ingest(db, history() + [
        blocked_at(location={"countryOrRegion": "US"}, deviceDetail={"deviceId": "dev-1"}),
        cumulative_grant("Mail.Read"),
        success_with(location={"countryOrRegion": "US"}, deviceDetail={"deviceId": "dev-NEW"}),
    ])

    (incident,) = bridged_incidents(db)
    assert [e["deviation_type"] for e in incident.escalation["evidence"]] == ["new_device"]
    assert incident.severity == "critical"


def test_a_familiar_context_does_not_escalate(db):
    ingest(db, history() + [
        blocked_at(location={"countryOrRegion": "US"}, deviceDetail={"deviceId": "dev-1"}),
        cumulative_grant("Mail.Read"),
        success_with(location={"countryOrRegion": "US"}, deviceDetail={"deviceId": "dev-1"}),
    ])

    (incident,) = bridged_incidents(db)
    assert incident.escalation["escalated"] is False
    assert incident.severity == "high"


def test_weak_deviations_do_not_escalate(db):
    """new_ip (ISP drift is normal - the lab showed it on identical
    activity), new_app (implied by 'blocked, then approved') and
    unusual_login_hour are real deviations but not intent evidence."""
    ingest(db, history() + [
        blocked_at(hhmmss="03:17:49", ipAddress="198.51.100.9", appId="app-blocked",
                   location={"countryOrRegion": "US"}, deviceDetail={"deviceId": "dev-1"}),
        cumulative_grant("Mail.Read", hhmmss="03:18:21.2"),
        success_with("success", "03:20:27", ipAddress="198.51.100.9", appId="app-blocked",
                     location={"countryOrRegion": "US"}, deviceDetail={"deviceId": "dev-1"}),
    ])

    seen = {d.deviation_type for d in db.query(BaselineDeviationRecord).all()}
    assert {"new_ip", "new_app"} <= seen  # they really were detected...

    (incident,) = bridged_incidents(db)
    assert incident.escalation["escalated"] is False  # ...and correctly ignored here
    assert incident.score_breakdown["behavioral_deviation"] == 0


def test_a_deviation_on_an_unrelated_event_does_not_escalate(db):
    """Only deviations on the chain's own events count."""
    ingest(db, history() + [
        {"source": "entra", "raw": {
            "id": "elsewhere", "createdDateTime": f"{DAY}12:00:00Z", "userPrincipalName": USER,
            "location": {"countryOrRegion": "RO"}, "status": {"errorCode": 0}}},
        blocked_at(location={"countryOrRegion": "US"}),
        cumulative_grant("Mail.Read"),
        success_with(location={"countryOrRegion": "US"}),
    ])

    (incident,) = bridged_incidents(db)
    assert incident.escalation["escalated"] is False


# ---- other rules are untouched ----

def test_attack_chain_rules_carry_no_cap_or_escalation(db):
    others = [r for r in load_correlation_rules() if r.id != "IDT-CORR-006"]

    assert others
    assert all(r.classification == "attack_chain" and r.severity_cap is None for r in others)
    assert all(r.escalation_deviations == [] for r in others)
