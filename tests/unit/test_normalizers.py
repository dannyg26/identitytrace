from datetime import datetime, timezone

from app.normalizers import entra, github, m365


def test_entra_signin_normalizes_device_code_flow():
    raw = {
        "id": "signin-1",
        "createdDateTime": "2026-09-09T17:02:11Z",
        "userPrincipalName": "alice@example.test",
        "appId": "app-123",
        "ipAddress": "203.0.113.25",
        "location": {"countryOrRegion": "US"},
        "deviceDetail": {"deviceId": "device-1", "browser": "Chrome 120"},
        "status": {"errorCode": 0},
        "authenticationProtocol": "deviceCode",
        "mfaDetail": {"result": "notRequired"},
        "sessionId": "sess-1",
    }
    event = entra.normalize(raw)

    assert event.source == "entra"
    assert event.event_type == "signin"
    assert event.result == "success"
    assert event.actor_id == "alice@example.test"
    assert event.auth_protocol == "deviceCode"
    assert event.ip_address == "203.0.113.25"
    assert event.geo_country == "US"
    assert event.raw_event_ref == raw


def test_entra_signin_derives_native_client_protocol_when_field_absent():
    """Real telemetry (Phase 9B, 2026-09): authenticationProtocol was
    never populated across 37 real sign-ins inspected, device-code
    included - not this specific field, at all, ever, in this tenant.
    clientAppUsed is what's actually present and reliably distinguishes
    native/desktop/CLI sign-ins from browser ones. See IDT-ENTRA-003 and
    docs/evaluation.md's Real-World Observability Findings."""
    raw = {
        "id": "signin-real-1",
        "createdDateTime": "2026-09-15T17:15:29Z",
        "userPrincipalName": "idt-test-user2@example.test",
        "appId": "14d82eec-204b-4c2f-b7e8-296a70dab67e",
        "ipAddress": "203.0.113.15",
        "clientAppUsed": "Mobile Apps and Desktop clients",
        "status": {"errorCode": 0},
    }
    event = entra.normalize(raw)

    assert event.auth_protocol == "nativeClient"


def test_entra_signin_browser_does_not_get_native_client_protocol():
    raw = {
        "id": "signin-real-2",
        "createdDateTime": "2026-09-15T17:00:00Z",
        "userPrincipalName": "alice@example.test",
        "clientAppUsed": "Browser",
        "status": {"errorCode": 0},
    }
    event = entra.normalize(raw)

    assert event.auth_protocol is None


def test_entra_signin_real_authenticationprotocol_still_takes_precedence():
    """If a future tenant/API version does populate authenticationProtocol
    directly, that real value must not be overridden by the clientAppUsed
    fallback - it's a fallback for when the field is absent, not a
    replacement when it's present."""
    raw = {
        "id": "signin-real-3",
        "createdDateTime": "2026-09-15T17:00:00Z",
        "userPrincipalName": "alice@example.test",
        "authenticationProtocol": "deviceCode",
        "clientAppUsed": "Mobile Apps and Desktop clients",
        "status": {"errorCode": 0},
    }
    event = entra.normalize(raw)

    assert event.auth_protocol == "deviceCode"


def test_entra_signin_admin_consent_required_surfaces_into_action():
    """Real telemetry (Phase 9B, 2026-09): AADSTS90094 occurred in the one
    real controlled attempt that requested an approval-requiring scope,
    and in 0 of 34 real benign sign-ins. See IDT-ENTRA-007."""
    raw = {
        "id": "signin-blocked-1",
        "createdDateTime": "2026-09-15T15:40:40Z",
        "userPrincipalName": "idt-test-user1@example.test",
        "status": {
            "errorCode": 90094,
            "failureReason": "Admin consent is required for the permissions requested by this application.",
        },
    }
    event = entra.normalize(raw)

    assert event.action == "admin_consent_required"
    assert event.result == "failure"


def test_entra_signin_other_failure_codes_keep_default_action():
    raw = {
        "id": "signin-other-fail",
        "createdDateTime": "2026-09-15T15:40:40Z",
        "userPrincipalName": "alice@example.test",
        "status": {"errorCode": 50199, "failureReason": "user confirmation required"},
    }
    event = entra.normalize(raw)

    assert event.action == "login"
    assert event.result == "failure"


def test_entra_audit_consent_extracts_scopes():
    raw = {
        "id": "audit-1",
        "category": "ApplicationManagement",
        "activityDateTime": "2026-09-09T17:04:02Z",
        "activityDisplayName": "Consent to application",
        "initiatedBy": {
            "user": {"id": "user-123", "userPrincipalName": "alice@example.test"}
        },
        "targetResources": [
            {
                "type": "Application",
                "id": "app-123",
                "displayName": "TestApp",
                "modifiedProperties": [
                    {
                        "displayName": "ConsentAction.Permissions",
                        "newValue": '["offline_access", "Files.Read.All"]',
                    }
                ],
            }
        ],
        "result": "success",
    }
    event = entra.normalize(raw)

    assert event.event_type == "oauth_consent"
    assert event.actor_id == "alice@example.test"
    assert event.app_id == "app-123"
    assert event.resource_id == "TestApp"
    assert set(event.permissions) == {"offline_access", "Files.Read.All"}


def test_entra_audit_delegated_permission_grant_extracts_real_scope_shape():
    """Found against real tenant telemetry (Phase 9B): the audit event that
    actually carries a newly-granted scope like Files.Read.All is
    'Add delegated permission grant' (not 'Consent to application', whose
    own ConsentAction.Permissions diff was a no-op in the real capture),
    and its DelegatedPermissionGrant.Scope value is one space-separated
    string, not a JSON array - real IdentityTrace missed this attack
    (IDT-ENTRA-001) until both were fixed."""
    raw = {
        "id": "audit-3",
        "category": "ApplicationManagement",
        "activityDateTime": "2026-09-15T15:42:07Z",
        "activityDisplayName": "Add delegated permission grant",
        "initiatedBy": {
            "user": {"id": "u1", "userPrincipalName": "idt-admin@example.test"}
        },
        "targetResources": [
            {
                "id": "sp-1",
                "displayName": "Microsoft Graph",
                "type": "ServicePrincipal",
                "modifiedProperties": [
                    {
                        "displayName": "DelegatedPermissionGrant.Scope",
                        "oldValue": '" openid profile User.Read"',
                        "newValue": '" openid profile User.Read Files.Read.All"',
                    }
                ],
            }
        ],
        "result": "success",
    }
    event = entra.normalize(raw)

    assert event.event_type == "oauth_consent"
    assert "Files.Read.All" in event.permissions


def test_entra_audit_initiated_by_app_does_not_crash():
    """Found against real tenant telemetry (Phase 9B): some directoryAudit
    events are initiated by an application, not a user, so
    initiatedBy.user is explicitly null (present, not merely absent) -
    `.get("user", {})` doesn't guard against that, only against a
    missing key."""
    raw = {
        "id": "audit-2",
        "category": "ApplicationManagement",
        "activityDateTime": "2026-09-09T17:05:00Z",
        "activityDisplayName": "Add application",
        "initiatedBy": {
            "user": None,
            "app": {"appId": "app-999", "displayName": "Some App"},
        },
        "targetResources": [],
        "result": "success",
    }
    event = entra.normalize(raw)

    assert event.actor_id == "unknown"
    assert event.ip_address is None


def test_github_clone_via_pat_is_normalized_as_repo_clone():
    raw = {
        "action": "git.clone",
        "actor": "alice",
        "actor_ip": "203.0.113.25",
        # GitHub's real documented field is country_name, not country_code -
        # see docs/normalizer-fidelity.md. This fixture previously used the
        # wrong field name AND this test never asserted on geo_country, so
        # the mismatch was invisible; both are fixed now.
        "actor_location": {"country_name": "United States"},
        "repo": "acme/secret-repo",
        "org": "acme",
        "token_id": "pat-1",
        "token_scopes": ["repo", "read:org"],
        "created_at": 1757430131000,
        "user_agent": "git/2.40",
    }
    event = github.normalize(raw)

    assert event.source == "github"
    assert event.event_type == "repo_clone"
    assert event.actor_type == "token"
    assert event.auth_protocol == "PAT"
    assert event.resource_id == "acme/secret-repo"
    assert event.resource_type == "repo"
    assert event.permissions == ["repo", "read:org"]
    assert event.geo_country == "United States"
    assert event.timestamp == datetime.fromtimestamp(1757430131, tz=timezone.utc)


def test_github_oauth_application_id_as_real_int_is_stringified():
    """Found against real personal-security-log telemetry (Phase 9B):
    oauth_application_id comes back as a real int
    (e.g. 5479418713), not a string - NormalizedEvent.app_id requires
    str, and every real event with this action crashed until fixed."""
    raw = {
        "action": "oauth_access.create",
        "actor": "alice",
        "oauth_application_id": 5479418713,
        "created_at": 1757430131000,
    }
    event = github.normalize(raw)

    assert event.app_id == "5479418713"


def test_github_repo_config_change_is_not_classified_as_repo_access():
    """Found against real telemetry (Phase 9B): repo.change_merge_setting
    (and repo.create, repo.add_topic, etc.) are not access events - only
    the literal 'repo.access' action is. Misclassifying them all as
    repo_access made IDT-GITHUB-001 fire on every token-authenticated
    config change, not just real access."""
    raw = {
        "action": "repo.change_merge_setting",
        "actor": "demo-user",
        "token_id": 123,
        "repo": "demo-user/idt-lab-repo1",
        "created_at": 1789489704900,
    }
    event = github.normalize(raw)

    assert event.event_type != "repo_access"


def test_github_user_action_without_token_is_actor_type_user():
    raw = {
        "action": "repo.access",
        "actor": "bob",
        "repo": "acme/public-repo",
        "created_at": "2026-09-09T18:00:00Z",
    }
    event = github.normalize(raw)

    assert event.actor_type == "user"
    assert event.event_type == "repo_access"
    assert event.auth_protocol is None


def test_m365_file_download_from_sharepoint():
    raw = {
        "Id": "m365-1",
        "CreationTime": "2026-09-09T09:10:00",
        "Operation": "FileDownloaded",
        "Workload": "SharePoint",
        "UserId": "alice@example.test",
        "ClientIP": "203.0.113.60",
        "ObjectId": "https://contoso.sharepoint.com/sites/finance/budget.xlsx",
        "ResultStatus": "Succeeded",
        "SizeInBytes": 500_000_000,
    }
    event = m365.normalize(raw)

    assert event.source == "m365"
    assert event.event_type == "file_download"
    assert event.result == "success"
    assert event.actor_id == "alice@example.test"
    assert event.resource_type == "file"
    assert event.bytes_transferred == 500_000_000
    assert event.raw_event_ref == raw
    # naive timestamp (no explicit timezone in the raw event) assumed UTC
    assert event.timestamp == datetime(2026, 9, 9, 9, 10, tzinfo=timezone.utc)


def test_m365_mailbox_forwarding_rule():
    raw = {
        "Id": "m365-2",
        "CreationTime": "2026-09-09T09:15:00Z",
        "Operation": "New-InboxRule",
        "Workload": "Exchange",
        "UserId": "bob@example.test",
        "ResultStatus": "Succeeded",
    }
    event = m365.normalize(raw)

    assert event.event_type == "mailbox_rule_change"
    assert event.resource_type == "mailbox"
    assert event.result == "success"


def test_m365_failed_operation_is_result_failure():
    raw = {
        "Id": "m365-3",
        "CreationTime": "2026-09-09T09:20:00Z",
        "Operation": "FileAccessed",
        "Workload": "OneDrive",
        "UserId": "carol@example.test",
        "ResultStatus": "Failed",
    }
    event = m365.normalize(raw)

    assert event.result == "failure"
    assert event.event_type == "file_access"


# ---- service_principal_id: the shared entity for entity-bridged correlation ----

_SP = "11111111-1111-4111-8111-111111111111"  # placeholder: Microsoft Graph Command Line Tools
_GRAPH_RESOURCE_SP = "33333333-3333-4333-8333-333333333333"  # placeholder: Microsoft Graph itself


def test_entra_signin_extracts_service_principal_id():
    raw = {
        "id": "sp-1", "createdDateTime": "2026-09-15T18:20:27Z",
        "userPrincipalName": "idt-test-user3@example.test",
        "servicePrincipalId": _SP, "status": {"errorCode": 0},
    }
    assert entra.normalize(raw).service_principal_id == _SP


def test_entra_signin_nil_guid_service_principal_is_not_an_entity():
    """Real telemetry: browser/portal sign-ins carry servicePrincipalId
    00000000-0000-0000-0000-000000000000. A placeholder must never be a
    shared entity - it would 'match' every other placeholder."""
    raw = {
        "id": "sp-nil", "createdDateTime": "2026-09-15T18:20:27Z",
        "userPrincipalName": "a@example.test",
        "servicePrincipalId": "00000000-0000-0000-0000-000000000000",
        "status": {"errorCode": 0},
    }
    assert entra.normalize(raw).service_principal_id is None


def test_entra_signin_missing_or_empty_service_principal_is_none():
    base = {"createdDateTime": "2026-09-15T18:20:27Z", "userPrincipalName": "a@example.test",
            "status": {"errorCode": 0}}
    assert entra.normalize({**base, "id": "sp-absent"}).service_principal_id is None
    assert entra.normalize({**base, "id": "sp-empty", "servicePrincipalId": ""}).service_principal_id is None
    assert entra.normalize({**base, "id": "sp-null", "servicePrincipalId": None}).service_principal_id is None


def test_entra_service_principal_id_is_lowercased_for_exact_matching():
    raw = {"id": "sp-case", "createdDateTime": "2026-09-15T18:20:27Z",
           "userPrincipalName": "a@example.test", "servicePrincipalId": _SP.upper(),
           "status": {"errorCode": 0}}
    assert entra.normalize(raw).service_principal_id == _SP


def _grant_event(**overrides):
    """Shaped like the real 'Add delegated permission grant' audit event:
    targetResources[0] is the RESOURCE service principal (Microsoft Graph),
    targetResources[1] is the CLIENT application's; the client's object ID
    is also given, JSON-quoted, in ServicePrincipal.ObjectID."""
    raw = {
        "id": "grant-1", "category": "ApplicationManagement",
        "activityDateTime": "2026-09-15T18:18:21.208964Z",
        "activityDisplayName": "Add delegated permission grant",
        "initiatedBy": {"user": {"id": "u", "userPrincipalName": "idt-admin@example.test"}},
        "targetResources": [
            {"type": "ServicePrincipal", "id": _GRAPH_RESOURCE_SP, "displayName": "Microsoft Graph",
             "modifiedProperties": [
                 {"displayName": "DelegatedPermissionGrant.Scope", "oldValue": '" openid"',
                  "newValue": '" openid Files.Read.All"'},
                 {"displayName": "ServicePrincipal.ObjectID", "oldValue": None, "newValue": f'"{_SP}"'},
             ]},
            {"type": "ServicePrincipal", "id": _SP, "displayName": None, "modifiedProperties": []},
        ],
        "result": "success",
    }
    raw.update(overrides)
    return raw


def test_entra_audit_grant_uses_the_client_service_principal_not_the_resource():
    """The trap: the first ServicePrincipal target on a real grant event is
    the *resource* (Microsoft Graph), not the client. Linking on it would
    silently join on the wrong entity."""
    event = entra.normalize(_grant_event())
    assert event.service_principal_id == _SP
    assert event.service_principal_id != _GRAPH_RESOURCE_SP


def test_entra_audit_without_objectid_property_has_no_service_principal():
    raw = _grant_event(targetResources=[
        {"type": "ServicePrincipal", "id": _SP, "displayName": "Microsoft Graph Command Line Tools",
         "modifiedProperties": [{"displayName": "ConsentContext.IsAdminConsent", "newValue": '"True"'}]},
    ], activityDisplayName="Consent to application")
    # Deliberately no fallback to "the first ServicePrincipal target".
    assert entra.normalize(raw).service_principal_id is None


def test_entra_audit_nil_or_malformed_objectid_is_none():
    nil = _grant_event()
    nil["targetResources"][0]["modifiedProperties"][1]["newValue"] = '"00000000-0000-0000-0000-000000000000"'
    assert entra.normalize(nil).service_principal_id is None
    bad = _grant_event()
    bad["targetResources"][0]["modifiedProperties"][1]["newValue"] = None
    assert entra.normalize(bad).service_principal_id is None
