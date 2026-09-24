"""A cross-identity incident must not misattribute the admin's step to the
requesting user - in the API (evidence carries the actor) AND on the
dashboard page an analyst actually reads. Found by exercising the real
incident through the app: the data was right but the page never named the
admin."""

import json

SP = "11111111-1111-4111-8111-111111111111"
USER = "idt-test-user3@example.test"
ADMIN = "idt-admin@example.test"


def _post(client, payload):
    r = client.post("/api/events", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


def _ingest_bridged_chain(client):
    _post(client, {"source": "entra", "raw": {
        "id": "blocked", "createdDateTime": "2026-09-15T18:17:49Z", "userPrincipalName": USER,
        "clientAppUsed": "Mobile Apps and Desktop clients", "servicePrincipalId": SP,
        "status": {"errorCode": 90094},
    }})
    _post(client, {"source": "entra", "raw": {
        "id": "consent", "category": "ApplicationManagement",
        "activityDateTime": "2026-09-15T18:18:21.208964Z",
        "activityDisplayName": "Add delegated permission grant",
        "initiatedBy": {"user": {"id": "a", "userPrincipalName": ADMIN}},
        "targetResources": [
            {"type": "ServicePrincipal", "id": "33333333-3333-4333-8333-333333333333",
             "displayName": "Microsoft Graph", "modifiedProperties": [
                 {"displayName": "DelegatedPermissionGrant.Scope", "newValue": json.dumps(" openid Files.Read.All")},
                 {"displayName": "ServicePrincipal.ObjectID", "newValue": json.dumps(SP)},
             ]},
            {"type": "ServicePrincipal", "id": SP, "displayName": None, "modifiedProperties": []},
        ],
        "result": "success",
    }})
    _post(client, {"source": "entra", "raw": {
        "id": "success", "createdDateTime": "2026-09-15T18:20:27Z", "userPrincipalName": USER,
        "clientAppUsed": "Mobile Apps and Desktop clients", "servicePrincipalId": SP,
        "status": {"errorCode": 0},
    }})
    return client.get("/api/incidents", params={"identity_id": USER}).json()


def test_api_attributes_each_step_to_who_did_it(client):
    (incident,) = _ingest_bridged_chain(client)

    assert incident["correlation_rule_id"] == "IDT-CORR-006"
    assert incident["identity_id"] == USER
    assert [e["actor_id"] for e in incident["evidence_reasons"]] == [USER, ADMIN, USER]


def test_dashboard_page_names_the_admin_on_the_consent_step_only(client):
    (incident,) = _ingest_bridged_chain(client)

    page = client.get(f"/incidents/{incident['incident_id']}")

    assert page.status_code == 200
    assert f"performed by {ADMIN}" in page.text
    # The requesting user's own steps are not annotated - only the bridge is.
    assert f"performed by {USER}" not in page.text


def test_identity_graph_for_the_incident_still_builds(client):
    (incident,) = _ingest_bridged_chain(client)

    graph = client.get(f"/api/incidents/{incident['incident_id']}/graph")

    assert graph.status_code == 200
    assert any(n["id"] == f"identity:{USER}" for n in graph.json()["nodes"])


def test_single_identity_incident_pages_get_no_performed_by_badges(client):
    """Regression: the existing rules' pages render exactly as before."""
    for raw in (
        {"id": "s1", "createdDateTime": "2026-09-09T09:00:00Z", "userPrincipalName": "m@example.test",
         "clientAppUsed": "Mobile Apps and Desktop clients", "status": {"errorCode": 0}},
    ):
        _post(client, {"source": "entra", "raw": raw})
    _post(client, {"source": "entra", "raw": {
        "id": "a1", "category": "ApplicationManagement", "activityDateTime": "2026-09-09T09:05:00Z",
        "activityDisplayName": "Consent to application",
        "initiatedBy": {"user": {"id": "m", "userPrincipalName": "m@example.test"}},
        "targetResources": [{"type": "Application", "id": "app-9", "displayName": "Evil",
                             "modifiedProperties": [{"displayName": "ConsentAction.Permissions",
                                                     "newValue": '["Files.Read.All"]'}]}],
        "result": "success"}})
    _post(client, {"timestamp": "2026-09-09T09:10:00Z", "source": "synthetic", "event_type": "file_access",
                   "action": "read", "result": "success", "actor_id": "m@example.test",
                   "actor_type": "user", "resource_type": "mailbox"})

    (incident,) = client.get("/api/incidents", params={"identity_id": "m@example.test"}).json()
    page = client.get(f"/incidents/{incident['incident_id']}")

    assert incident["correlation_rule_id"] == "IDT-CORR-001"
    assert page.status_code == 200
    assert "performed by" not in page.text


# ---- workflow-review semantics reach the API and the page an analyst reads ----

def test_the_incident_is_labelled_a_workflow_review_in_the_api(client):
    (incident,) = _ingest_bridged_chain(client)

    assert incident["classification"] == "workflow_review"
    assert incident["escalation"]["severity_cap"] == "high"
    assert incident["escalation"]["escalated"] is False
    assert "analyst review" in incident["correlation_rule_title"]


def test_the_page_says_workflow_review_not_compromise_and_explains_the_cap(client):
    (incident,) = _ingest_bridged_chain(client)

    page = client.get(f"/incidents/{incident['incident_id']}")

    assert page.status_code == 200
    assert "Workflow review - not a compromise finding" in page.text
    assert "No independent escalation evidence found" in page.text


def test_single_identity_incident_pages_have_no_workflow_review_note(client):
    """Regression: attack_chain incidents render exactly as before."""
    _post(client, {"source": "entra", "raw": {
        "id": "s1", "createdDateTime": "2026-09-09T09:00:00Z", "userPrincipalName": "m@example.test",
        "clientAppUsed": "Mobile Apps and Desktop clients", "status": {"errorCode": 0}}})
    _post(client, {"source": "entra", "raw": {
        "id": "a1", "category": "ApplicationManagement", "activityDateTime": "2026-09-09T09:05:00Z",
        "activityDisplayName": "Consent to application",
        "initiatedBy": {"user": {"id": "m", "userPrincipalName": "m@example.test"}},
        "targetResources": [{"type": "Application", "id": "app-9", "displayName": "Evil",
                             "modifiedProperties": [{"displayName": "ConsentAction.Permissions",
                                                     "newValue": '["Files.Read.All"]'}]}],
        "result": "success"}})
    _post(client, {"timestamp": "2026-09-09T09:10:00Z", "source": "synthetic", "event_type": "file_access",
                   "action": "read", "result": "success", "actor_id": "m@example.test",
                   "actor_type": "user", "resource_type": "mailbox"})

    (incident,) = client.get("/api/incidents", params={"identity_id": "m@example.test"}).json()
    page = client.get(f"/incidents/{incident['incident_id']}")

    assert incident["classification"] == "attack_chain"
    assert incident["escalation"] is None
    assert "workflow-review-note" not in page.text


def test_correlation_rules_endpoint_exposes_the_classification(client):
    rules = {r["id"]: r for r in client.get("/api/correlation-rules").json()}

    assert rules["IDT-CORR-006"]["classification"] == "workflow_review"
    assert rules["IDT-CORR-006"]["escalation_deviations"] == ["new_country", "new_device"]
    assert rules["IDT-CORR-001"]["classification"] == "attack_chain"
