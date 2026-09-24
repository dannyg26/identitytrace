"""Unit tests for the workflow-review semantics: schema validation, the
severity-ceiling helper, and grant-delta extraction in the Entra normalizer."""

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.baselines.deviation import DEVIATION_TYPES, evaluate_deviations
from app.baselines.profile import IdentityProfile
from app.correlation.schema import CorrelationRule
from app.correlation.scoring import score_ceiling_for_severity
from app.models.event import NormalizedEvent
from app.normalizers import entra


def _rule(**overrides):
    base = dict(id="X", title="t", window_seconds=60, sequence=["a", "b"], score_bonus=5)
    base.update(overrides)
    return CorrelationRule(**base)


# ---- schema ----

def test_default_classification_is_attack_chain():
    rule = _rule()
    assert rule.classification == "attack_chain"
    assert rule.severity_cap is None
    assert rule.escalation_deviations == []


def test_workflow_review_requires_a_severity_cap():
    with pytest.raises(ValidationError, match="severity_cap"):
        _rule(classification="workflow_review")


@pytest.mark.parametrize("extra", [dict(severity_cap="high"), dict(escalation_deviations=["new_country"])])
def test_cap_and_escalation_are_rejected_on_attack_chain_rules(extra):
    with pytest.raises(ValidationError, match="workflow_review"):
        _rule(**extra)


def test_escalation_deviations_must_be_types_the_baseline_layer_can_produce():
    with pytest.raises(ValidationError, match="no telemetry"):
        _rule(classification="workflow_review", severity_cap="high",
              escalation_deviations=["publisher_unverified"])


def test_severity_cap_cannot_be_critical():
    with pytest.raises(ValidationError):
        _rule(classification="workflow_review", severity_cap="critical")


def test_deviation_types_constant_matches_what_the_layer_actually_emits():
    """DEVIATION_TYPES gates which signals a rule may cite as evidence; it
    must equal the set evaluate_deviations can really produce."""
    profile = IdentityProfile(
        actor_id="u", event_count=10, known_devices={"d0"}, known_ips={"1.1.1.1"},
        known_countries={"US"}, known_apps={"a0"}, known_auth_protocols={"interactive"},
        login_hours={9}, max_bytes_transferred=10,
    )
    event = NormalizedEvent(
        timestamp=datetime(2026, 9, 1, 3, 0, tzinfo=timezone.utc), source="entra", event_type="signin",
        action="login", result="success", actor_id="u", actor_type="user", device_id="d9",
        ip_address="2.2.2.2", geo_country="RO", app_id="a9", auth_protocol="basic", bytes_transferred=1000,
    )

    assert {d.deviation_type for d in evaluate_deviations(event, profile)} == set(DEVIATION_TYPES)


# ---- severity ceiling ----

@pytest.mark.parametrize("severity,ceiling", [("critical", 100), ("high", 84), ("medium", 69), ("low", 29)])
def test_score_ceiling_is_one_below_the_next_band(severity, ceiling):
    assert score_ceiling_for_severity(severity) == ceiling


# ---- grant delta extraction ----

def _grant(old, new):
    props = {"displayName": "DelegatedPermissionGrant.Scope"}
    if old is not None:
        props["oldValue"] = json.dumps(old)
    if new is not None:
        props["newValue"] = json.dumps(new)
    return {
        "id": "a1", "category": "ApplicationManagement", "activityDateTime": "2026-09-15T18:18:21Z",
        "activityDisplayName": "Add delegated permission grant",
        "initiatedBy": {"user": {"id": "u", "userPrincipalName": "admin@example.test"}},
        "targetResources": [{"type": "ServicePrincipal", "id": "g", "modifiedProperties": [props]}],
        "result": "success",
    }


def test_delta_excludes_scopes_already_granted():
    event = entra.normalize(_grant(" openid offline_access", " openid offline_access Mail.Read"))
    assert event.permissions == ["Mail.Read"]


def test_no_old_value_means_everything_in_the_grant_is_new():
    event = entra.normalize(_grant(None, " openid Files.Read.All"))
    assert event.permissions == ["openid", "Files.Read.All"]


def test_regranting_the_same_scopes_adds_nothing():
    event = entra.normalize(_grant(" openid Mail.Read", " openid Mail.Read"))
    assert event.permissions == []


def test_removing_a_scope_adds_nothing():
    event = entra.normalize(_grant(" openid Mail.Read", " openid"))
    assert event.permissions == []


def test_a_revoked_grant_with_no_new_value_adds_nothing():
    event = entra.normalize(_grant(" openid Mail.Read", None))
    assert event.permissions == []


def test_unparseable_old_value_falls_back_to_treating_the_grant_as_new():
    raw = _grant(None, " openid Mail.Read")
    raw["targetResources"][0]["modifiedProperties"][0]["oldValue"] = "not json {"
    assert entra.normalize(raw).permissions == ["openid", "Mail.Read"]


def test_the_cumulative_value_is_still_available_as_raw_evidence():
    event = entra.normalize(_grant(" openid offline_access", " openid offline_access Mail.Read"))
    prop = event.raw_event_ref["targetResources"][0]["modifiedProperties"][0]
    assert json.loads(prop["newValue"]) == " openid offline_access Mail.Read"


def test_consent_action_permissions_arrays_are_unaffected():
    raw = _grant(None, None)
    raw["activityDisplayName"] = "Consent to application"
    raw["targetResources"] = [{"type": "Application", "id": "app", "displayName": "X", "modifiedProperties": [
        {"displayName": "ConsentAction.Permissions", "newValue": '["Files.Read.All", "offline_access"]'}]}]
    assert entra.normalize(raw).permissions == ["Files.Read.All", "offline_access"]
