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
