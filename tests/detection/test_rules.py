"""Per-rule detection tests: one positive and multiple negative cases for
every loaded rule (blueprint §10.4 test pyramid requirement).

This loads the real YAML files under detections/ - these tests exercise
the actual rule definitions shipped in the repo, not a copy of their logic.
"""

from datetime import datetime, timezone

import pytest

from app.detections.engine import evaluate_rule
from app.detections.loader import load_rules
from app.models.event import NormalizedEvent

RULES = {r.id: r for r in load_rules()}


def _evt(**overrides) -> NormalizedEvent:
    kwargs = dict(
        timestamp=datetime(2026, 9, 9, 17, 0, tzinfo=timezone.utc),
        source="entra",
        event_type="signin",
        action="login",
        result="success",
        actor_id="alice@example.test",
        actor_type="user",
    )
    kwargs.update(overrides)
    return NormalizedEvent(**kwargs)


# rule_id -> one event that MUST trigger it
POSITIVE_CASES: dict[str, dict] = {
    "IDT-ENTRA-001": dict(
        source="entra", event_type="oauth_consent", action="grant_permission",
        permissions=["Files.Read.All"],
    ),
    "IDT-ENTRA-002": dict(
        source="entra", event_type="oauth_consent", action="grant_permission",
        permissions=["offline_access"],
    ),
    "IDT-ENTRA-003": dict(
        source="entra", event_type="signin", auth_protocol="nativeClient", result="success",
    ),
    "IDT-ENTRA-004": dict(
        source="entra", event_type="signin", auth_protocol="interactive",
        result="success", mfa_result="not_present",
    ),
    "IDT-ENTRA-005": dict(
        source="entra", event_type="signin", auth_protocol="basic", result="success",
    ),
    "IDT-ENTRA-006": dict(
        source="entra", event_type="audit", action="Add member to role", result="success",
    ),
    "IDT-ENTRA-007": dict(
        source="entra", event_type="signin", action="admin_consent_required", result="failure",
    ),
    "IDT-GITHUB-001": dict(
        source="github", event_type="repo_clone", actor_type="token",
    ),
    "IDT-GITHUB-002": dict(
        source="github", event_type="repo_clone", actor_type="token",
        bytes_transferred=200_000_000,
    ),
    "IDT-GITHUB-003": dict(
        source="github", event_type="repo_access", actor_type="token",
        resource_id="acme/secret-repo",
    ),
    "IDT-GITHUB-004": dict(
        source="github", event_type="token_event", permissions=["admin:org"],
    ),
    "IDT-XDOMAIN-001": dict(
        source="synthetic", event_type="file_download", bytes_transferred=300_000_000,
    ),
    "IDT-XDOMAIN-002": dict(
        source="synthetic", event_type="file_access", resource_type="mailbox", result="success",
    ),
    "IDT-M365-001": dict(
        source="m365", event_type="mailbox_rule_change", action="New-InboxRule", result="success",
    ),
}

# rule_id -> several events that must NOT trigger it, each falsifying exactly
# one condition of the positive case above.
NEGATIVE_CASES: dict[str, list[dict]] = {
    "IDT-ENTRA-001": [
        dict(source="entra", event_type="signin", permissions=["Files.Read.All"]),  # wrong event_type
        dict(source="entra", event_type="oauth_consent", permissions=["offline_access"]),  # not a data scope
    ],
    "IDT-ENTRA-002": [
        dict(source="entra", event_type="oauth_consent", permissions=["Mail.Read"]),  # no offline_access
        dict(source="entra", event_type="signin", permissions=["offline_access"]),  # wrong event_type
    ],
    "IDT-ENTRA-003": [
        dict(source="entra", event_type="signin", auth_protocol="nativeClient", result="failure"),
        dict(source="entra", event_type="signin", auth_protocol="interactive", result="success"),
    ],
    "IDT-ENTRA-004": [
        dict(source="entra", event_type="signin", auth_protocol="interactive", result="success", mfa_result="success"),
        dict(source="entra", event_type="signin", auth_protocol="interactive", result="failure", mfa_result="not_present"),
    ],
    "IDT-ENTRA-005": [
        dict(source="entra", event_type="signin", auth_protocol="interactive", result="success"),
        dict(source="entra", event_type="signin", auth_protocol="basic", result="failure"),
    ],
    "IDT-ENTRA-006": [
        dict(source="entra", event_type="audit", action="Consent to application", result="success"),
        dict(source="entra", event_type="signin", action="Add member to role", result="success"),
        dict(source="entra", event_type="audit", action="Add member to role", result="failure"),
    ],
    "IDT-ENTRA-007": [
        dict(source="entra", event_type="signin", action="login", result="failure"),  # a different failure reason
        dict(source="entra", event_type="audit", action="admin_consent_required", result="failure"),  # wrong event_type
    ],
    "IDT-GITHUB-001": [
        dict(source="github", event_type="repo_clone", actor_type="user"),
        dict(source="github", event_type="token_event", actor_type="token"),
    ],
    "IDT-GITHUB-002": [
        dict(source="github", event_type="repo_clone", actor_type="token", bytes_transferred=1_000),
        dict(source="github", event_type="repo_clone", actor_type="user", bytes_transferred=200_000_000),
        dict(source="github", event_type="repo_clone", actor_type="token", bytes_transferred=None),
    ],
    "IDT-GITHUB-003": [
        dict(source="github", event_type="repo_access", actor_type="token", resource_id="acme/public-repo"),
        dict(source="github", event_type="repo_access", actor_type="user", resource_id="acme/secret-repo"),
    ],
    "IDT-GITHUB-004": [
        dict(source="github", event_type="token_event", permissions=["repo"]),
        dict(source="github", event_type="repo_clone", permissions=["admin:org"]),
    ],
    "IDT-XDOMAIN-001": [
        dict(source="synthetic", event_type="file_download", bytes_transferred=1_000),
        dict(source="synthetic", event_type="file_download", bytes_transferred=None),
    ],
    "IDT-XDOMAIN-002": [
        dict(source="synthetic", event_type="file_access", resource_type="repo", result="success"),
        dict(source="synthetic", event_type="file_access", resource_type="mailbox", result="failure"),
    ],
    "IDT-M365-001": [
        dict(source="m365", event_type="file_download", action="FileDownloaded", result="success"),  # wrong event_type
        dict(source="m365", event_type="mailbox_rule_change", action="New-InboxRule", result="failure"),
    ],
}


def test_every_loaded_rule_has_test_coverage():
    """Guards against a new rule being added without tests for it."""
    assert set(POSITIVE_CASES) == set(RULES)
    assert set(NEGATIVE_CASES) == set(RULES)
    for rule_id, cases in NEGATIVE_CASES.items():
        assert len(cases) >= 2, f"{rule_id} needs at least 2 negative cases"


@pytest.mark.parametrize("rule_id", sorted(POSITIVE_CASES))
def test_rule_positive_case_fires(rule_id):
    rule = RULES[rule_id]
    match = evaluate_rule(rule, _evt(**POSITIVE_CASES[rule_id]))
    assert match is not None, f"{rule_id} should have fired on its positive fixture"
    assert match.reasons  # every match carries an explanation


@pytest.mark.parametrize(
    "rule_id,case_index",
    [(rule_id, i) for rule_id, cases in NEGATIVE_CASES.items() for i in range(len(cases))],
)
def test_rule_negative_cases_do_not_fire(rule_id, case_index):
    rule = RULES[rule_id]
    event = _evt(**NEGATIVE_CASES[rule_id][case_index])
    match = evaluate_rule(rule, event)
    assert match is None, f"{rule_id} should NOT have fired on negative case #{case_index}"


# ---- IDT-ENTRA-003 v3: exactly two equivalent representations ----

@pytest.mark.parametrize("protocol", ["nativeClient", "deviceCode"])
def test_entra_003_accepts_both_equivalent_representations(protocol):
    """v2 (telemetry-model change) silently dropped the documented
    authenticationProtocol == deviceCode; v3 restores it alongside the
    derived nativeClient value. Compatibility restoration, not a new
    detection."""
    event = _evt(auth_protocol=protocol, result="success")
    assert evaluate_rule(RULES["IDT-ENTRA-003"], event) is not None


@pytest.mark.parametrize(
    "protocol", ["interactive", "basic", "ropc", "nativeclient", "devicecode", "", None]
)
def test_entra_003_does_not_broaden_beyond_those_two(protocol):
    """Case-sensitive, exact: near-misses and every other protocol value
    still do not match."""
    event = _evt(auth_protocol=protocol, result="success")
    assert evaluate_rule(RULES["IDT-ENTRA-003"], event) is None


@pytest.mark.parametrize("protocol", ["nativeClient", "deviceCode"])
def test_entra_003_still_requires_a_successful_sign_in(protocol):
    assert evaluate_rule(RULES["IDT-ENTRA-003"], _evt(auth_protocol=protocol, result="failure")) is None
