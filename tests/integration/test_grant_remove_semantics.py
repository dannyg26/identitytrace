"""'Remove delegated permission grant' next to an 'Add' (real Entra shape).

Found in real exports: an update to an existing grant is logged as an Add
plus a Remove ~1-4 ms later - same correlationId, actor, IP, targets and the
same old/new scope values as each other (each event's own old != new: the
Remove is not a reduction). A Remove/Unassign record cannot grant anything,
so it carries no permissions and must not be scored as a second consent.
"""

import copy
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.correlation.loader import load_correlation_rules
from app.detections.loader import load_rules
from app.models.db import Base
from app.models.detection import DetectionMatchRecord
from app.normalizers import entra
from app.pipeline import normalize_payload, process_event
from tests.integration.test_correlation_bridged_pipeline import (
    ADMIN,
    DAY,
    GRAPH_RESOURCE_SP,
    SP,
    blocked,
    bridged_incidents,
    succeeds,
)

PRIOR = " openid profile User.Read offline_access"


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = Session(engine)
    yield session
    session.close()


def add_grant(added="Mail.Read", prior=PRIOR, event_id="add", hhmmss="18:18:21.208964"):
    old = json.dumps(prior) if prior is not None else None
    new = json.dumps((prior or "") + " " + added)
    return {
        "id": event_id, "category": "ApplicationManagement", "activityDateTime": f"{DAY}{hhmmss}Z",
        "activityDisplayName": "Add delegated permission grant", "operationType": "Assign",
        "correlationId": "corr-1",
        "initiatedBy": {"user": {"id": "admin-id", "userPrincipalName": ADMIN, "ipAddress": "203.0.113.18"}},
        "targetResources": [
            {"type": "ServicePrincipal", "id": GRAPH_RESOURCE_SP, "displayName": "Microsoft Graph",
             "modifiedProperties": [
                 {"displayName": "DelegatedPermissionGrant.Scope", "oldValue": old, "newValue": new},
                 {"displayName": "ServicePrincipal.ObjectID", "oldValue": None, "newValue": json.dumps(SP)},
             ]},
            {"type": "ServicePrincipal", "id": SP, "displayName": None, "modifiedProperties": []},
        ],
        "result": "success",
    }


def paired_remove(add, event_id="remove", hhmmss="18:18:21.209967"):
    """The real Remove: the Add with only name, time and operationType changed."""
    r = copy.deepcopy(add)
    r.update(id=event_id, activityDisplayName="Remove delegated permission grant",
             operationType="Unassign", activityDateTime=f"{DAY}{hhmmss}Z")
    return r


def _envelope(raw):
    return {"source": "entra", "raw": raw}


def _ingest(db, payloads):
    rules, corr = load_rules(), load_correlation_rules()
    for p in payloads:
        process_event(db, normalize_payload(p), rules, corr)


def _matches(db, event_id):
    return sorted(m.rule_id for m in db.query(DetectionMatchRecord).filter_by(event_id=event_id).all())


def test_the_real_pair_differs_only_in_name_time_and_operation_type():
    """Guards the premise these tests rest on, using the real shape."""
    add = add_grant()
    remove = paired_remove(add)

    assert {k for k in add if add[k] != remove[k]} == {"id", "activityDisplayName", "activityDateTime", "operationType"}
    scope = add["targetResources"][0]["modifiedProperties"][0]
    assert scope["oldValue"] != scope["newValue"]  # not a no-op: old == new does NOT hold


def test_the_add_carries_the_grant_and_the_paired_remove_carries_nothing():
    add = add_grant()

    assert entra.normalize(add).permissions == ["Mail.Read"]
    assert entra.normalize(paired_remove(add)).permissions == []


def test_a_remove_is_still_recorded_as_an_event_not_dropped():
    remove = entra.normalize(paired_remove(add_grant()))

    assert remove.action == "Remove delegated permission grant"
    assert remove.event_type == "oauth_consent"
    assert remove.service_principal_id == SP
    assert remove.raw_event_ref["operationType"] == "Unassign"


def test_a_genuine_reduction_is_not_scored_as_a_grant():
    """old contains a risky scope that new no longer has: a revocation."""
    reduction = paired_remove(add_grant())
    scope = reduction["targetResources"][0]["modifiedProperties"][0]
    scope["oldValue"], scope["newValue"] = json.dumps(PRIOR + " Mail.Read"), json.dumps(PRIOR)

    assert entra.normalize(reduction).permissions == []


def test_one_consent_action_produces_one_alert_not_two(db):
    add = add_grant()
    _ingest(db, [_envelope(add), _envelope(paired_remove(add))])

    assert _matches(db, "add") == ["IDT-ENTRA-001"]
    assert _matches(db, "remove") == []


def test_a_lone_remove_is_not_a_consent_alert(db):
    """Documented trade-off: if only the Remove of a pair were ever exported,
    the grant would go unscored. Both land within ~4 ms with one correlationId,
    so this needs an export boundary inside that gap."""
    _ingest(db, [_envelope(paired_remove(add_grant()))])

    assert _matches(db, "remove") == []


def test_the_first_grant_has_no_remove_and_is_scored_as_before(db):
    _ingest(db, [_envelope(add_grant(added="Files.Read.All offline_access", prior=None))])

    assert _matches(db, "add") == ["IDT-ENTRA-001", "IDT-ENTRA-002"]


def test_the_workflow_incident_is_unchanged_with_the_real_pair_present(db):
    add = add_grant()
    _ingest(db, [blocked(), _envelope(add), _envelope(paired_remove(add)), succeeds()])

    (incident,) = bridged_incidents(db)
    assert incident.evidence_ids == ["blocked", "add", "success"]  # cites the Add
    assert (incident.score, incident.severity) == (75, "high")
    assert incident.score_breakdown["event_risk"] == 65


# ---- a GENUINE revocation (real experiment, 2026-09-21) ----
#
# Removing Mail.ReadWrite from the admin-consented grant was logged the same
# way as an update: an Add + Remove pair (Assign/Unassign, 2 ms apart, one
# correlationId, identical values in both) - not a standalone Remove and not a
# different event type. The only difference from a growth pair is direction:
# newValue is a SUBSET of oldValue. The Add of that pair still says "Add".

FULL = " openid profile User.Read offline_access Files.Read.All Mail.Read Mail.ReadWrite"
AFTER_REVOKE = "openid profile User.Read offline_access Files.Read.All Mail.Read"  # real: leading space also dropped


def reduction_add(event_id="rev-add", hhmmss="18:18:21.565472", old=FULL, new=AFTER_REVOKE):
    raw = add_grant(event_id=event_id, hhmmss=hhmmss)
    scope = raw["targetResources"][0]["modifiedProperties"][0]
    scope["oldValue"], scope["newValue"] = json.dumps(old), json.dumps(new)
    return raw


def test_a_real_revocation_is_the_same_pair_shape_as_an_update():
    add = reduction_add()
    remove = paired_remove(add, event_id="rev-remove", hhmmss="18:18:21.567471")

    assert {k for k in add if add[k] != remove[k]} == {"id", "activityDisplayName", "activityDateTime", "operationType"}
    scope = add["targetResources"][0]["modifiedProperties"][0]
    assert set(json.loads(scope["newValue"]).split()) < set(json.loads(scope["oldValue"]).split())  # a reduction


@pytest.mark.parametrize("build", [
    lambda: reduction_add(),
    lambda: paired_remove(reduction_add(), event_id="rev-remove", hhmmss="18:18:21.567471"),
])
def test_neither_half_of_a_revocation_carries_permissions(build):
    """The Add half says 'Add' but removed a scope: new - old is empty."""
    assert entra.normalize(build()).permissions == []


def test_a_revocation_raises_no_consent_alert_even_though_risky_scopes_remain(db):
    """Files.Read.All, Mail.Read and offline_access are all still in the grant
    after the revocation. Scoring the cumulative newValue would alert on every
    one of them (16 alerts across the real experiment's 8 grant events)."""
    add = reduction_add()
    _ingest(db, [_envelope(add), _envelope(paired_remove(add, event_id="rev-remove", hhmmss="18:18:21.567471"))])

    assert _matches(db, "rev-add") == []
    assert _matches(db, "rev-remove") == []


def test_removing_a_scope_that_was_never_risky_is_equally_silent(db):
    """The helper-scope drop in the real experiment."""
    old = AFTER_REVOKE + " DelegatedPermissionGrant.ReadWrite.All"
    _ingest(db, [_envelope(reduction_add(event_id="drop", old=old, new=AFTER_REVOKE))])

    assert _matches(db, "drop") == []


def test_a_revocation_cannot_complete_the_workflow_chain(db):
    """block -> revocation pair -> success is not 'admin grants consent'."""
    add = reduction_add(hhmmss="18:18:21.565472")
    _ingest(db, [blocked(), _envelope(add), _envelope(paired_remove(add, event_id="rev-remove", hhmmss="18:18:21.567471")),
                 succeeds()])

    assert bridged_incidents(db) == []
