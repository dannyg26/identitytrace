"""Validate every normalizer against fixtures shaped like each source's
*real, officially-published* API schema - not fixtures this project
invented for its own convenience. See tests/fixtures/real_samples/README.md
for exact sources and what this check actually found and fixed.

This is a fidelity check, not a fresh dataset: it doesn't change what the
detection engine measures (docs/evaluation.md's numbers are unaffected),
but it answers a different, important question - would this code survive
contact with a real Entra/GitHub/M365 tenant's actual export, or only
with the shapes this project happened to invent for itself?
"""

import json
from pathlib import Path

from app.normalizers import entra, github, m365

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "real_samples"


def _load(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def test_entra_signin_devicecode_real_schema():
    raw = _load("entra_signin_devicecode.json")
    event = entra.normalize(raw)

    assert event.source == "entra"
    assert event.event_type == "signin"
    assert event.auth_protocol == "deviceCode"
    assert event.result == "success"
    assert event.actor_id == "priya.k@contoso-example.test"
    assert event.device_id == "c3d4e5f6-0003-4000-8000-000000000003"
    assert event.geo_country == "RU"
    # mfaDetail is absent (deprecated, correctly omitted) - MFA strength
    # must come from the real, current authenticationRequirement field.
    assert "mfaDetail" not in raw
    assert event.mfa_result == "not_present"


def test_entra_audit_oauth_consent_real_schema():
    raw = _load("entra_audit_oauth_consent.json")
    event = entra.normalize(raw)

    assert event.event_type == "oauth_consent"
    assert event.actor_id == "priya.k@contoso-example.test"
    assert event.app_id == "f6a7b8c9-0006-4000-8000-000000000006"
    assert event.resource_id == "Reporting Sync Tool"
    assert set(event.permissions) == {"Files.Read.All", "offline_access"}
    # the real directoryAudit "category" field ("ApplicationManagement")
    # must NOT be mistaken for a dispatch marker - see normalize()'s
    # docstring for the bug this fixture caught.
    assert raw["category"] == "ApplicationManagement"


def test_entra_audit_role_assignment_real_schema():
    raw = _load("entra_audit_role_assignment.json")
    event = entra.normalize(raw)

    assert event.event_type == "audit"
    assert event.action == "Add member to role"
    assert event.actor_id == "priya.k@contoso-example.test"
    assert event.result == "success"


def test_github_pat_clone_real_schema():
    raw = _load("github_audit_pat_clone.json")
    event = github.normalize(raw)

    assert event.source == "github"
    assert event.event_type == "repo_clone"
    assert event.actor_type == "token"
    assert event.actor_id == "dev-jsmith"
    assert event.resource_id == "acme-corp/payments-secrets"
    assert event.geo_country == "Russian Federation"  # a name, not a code - see README
    assert event.permissions == ["repo", "read:org"]


def test_m365_file_downloaded_real_schema():
    raw = _load("m365_file_downloaded.json")
    event = m365.normalize(raw)

    assert event.source == "m365"
    assert event.event_type == "file_download"
    assert event.result == "success"
    assert event.resource_type == "file"
    assert "Q3-Budget.xlsx" in event.resource_id


def test_m365_partially_succeeded_maps_to_partial_not_failure():
    """The real bug this fixture caught: ResultStatus: PartiallySucceeded
    was being folded into "failure" instead of this project's own
    unused-until-now `result="partial"` value."""
    raw = _load("m365_mailbox_rule_partial.json")
    event = m365.normalize(raw)

    assert raw["ResultStatus"] == "PartiallySucceeded"
    assert event.result == "partial"
