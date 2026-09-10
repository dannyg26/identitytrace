"""Integration tests for the Phase 4 exit criterion (and the blueprint's
MVP cut line): related signals for one identity, within a time window,
correlate into a single incident with explainable score/confidence -
rather than staying disconnected alerts.
"""


def _ingest_full_chain(client, actor_id="mallory@example.test"):
    """A1/A2/A6-flavored chain: new device-code session -> risky OAuth
    consent -> mailbox access, 5 minutes apart - satisfies IDT-CORR-001."""
    r1 = client.post(
        "/api/events",
        json={
            "source": "entra",
            "raw": {
                "id": "signin-mallory-1",
                "createdDateTime": "2026-09-09T09:00:00Z",
                "userPrincipalName": actor_id,
                "appId": "app-999",
                "ipAddress": "203.0.113.50",
                "status": {"errorCode": 0},
                "authenticationProtocol": "deviceCode",
            },
        },
    )
    r2 = client.post(
        "/api/events",
        json={
            "source": "entra",
            "raw": {
                "id": "audit-mallory-1",
                "category": "ApplicationManagement",
                "activityDateTime": "2026-09-09T09:05:00Z",
                "activityDisplayName": "Consent to application",
                "initiatedBy": {
                    "user": {"id": "mallory-id", "userPrincipalName": actor_id}
                },
                "targetResources": [
                    {
                        "type": "Application",
                        "id": "app-999",
                        "displayName": "EvilApp",
                        "modifiedProperties": [
                            {
                                "displayName": "ConsentAction.Permissions",
                                "newValue": '["Files.Read.All"]',
                            }
                        ],
                    }
                ],
                "result": "success",
            },
        },
    )
    r3 = client.post(
        "/api/events",
        json={
            "timestamp": "2026-09-09T09:10:00Z",
            "source": "synthetic",
            "event_type": "file_access",
            "action": "read",
            "result": "success",
            "actor_id": actor_id,
            "actor_type": "user",
            "resource_type": "mailbox",
        },
    )
    assert r1.status_code == 201, r1.text
    assert r2.status_code == 201, r2.text
    assert r3.status_code == 201, r3.text
    return r1.json(), r2.json(), r3.json()


def test_correlation_rules_are_loaded(client):
    rules = client.get("/api/correlation-rules").json()
    assert len(rules) == 5
    assert "IDT-CORR-001" in {r["id"] for r in rules}


def test_no_incident_until_the_full_chain_is_present(client):
    r1 = client.post(
        "/api/events",
        json={
            "source": "entra",
            "raw": {
                "id": "signin-partial-1",
                "createdDateTime": "2026-09-09T09:00:00Z",
                "userPrincipalName": "partial@example.test",
                "appId": "app-1",
                "status": {"errorCode": 0},
                "authenticationProtocol": "deviceCode",
            },
        },
    )
    assert r1.status_code == 201
    assert client.get("/api/incidents", params={"identity_id": "partial@example.test"}).json() == []


def test_full_chain_creates_one_explainable_incident(client):
    e1, e2, e3 = _ingest_full_chain(client)

    incidents = client.get("/api/incidents", params={"identity_id": "mallory@example.test"}).json()
    assert len(incidents) == 1
    incident = incidents[0]

    assert incident["correlation_rule_id"] == "IDT-CORR-001"
    assert incident["attack_chain"] == [
        "new_session_context",
        "risky_oauth_consent",
        "sensitive_resource_access",
    ]
    assert incident["evidence_ids"] == [e1["event_id"], e2["event_id"], e3["event_id"]]
    assert incident["status"] == "open"
    assert incident["analyst_disposition"] is None

    # event_risk = 15 (IDT-ENTRA-003) + 35 (IDT-ENTRA-001) + 30 (IDT-XDOMAIN-002) = 80
    # behavioral_deviation = 0 (fresh identity, under the min-history floor)
    # temporal_chain_bonus = 40 (this rule's score_bonus) -> 120, clamped to 100
    assert incident["score"] == 100
    assert incident["severity"] == "critical"
    assert incident["score_breakdown"] == {
        "event_risk": 80,
        "behavioral_deviation": 0,
        "temporal_chain_bonus": 40,
    }

    # correlation_strength = 1 - (600s span / 900s window) = 1/3
    # evidence_quality = 3-step sequence / 4 = 0.75
    # telemetry_completeness = 2/3 raw-evidenced events (the synthetic one has none)
    # confidence = 0.4*(1/3) + 0.3*0.75 + 0.3*(2/3) = 0.5583... -> 0.56
    assert incident["confidence"] == 0.56
    assert incident["confidence_breakdown"]["telemetry_completeness"] == round(2 / 3, 2)

    assert len(incident["evidence_reasons"]) == 3
    assert incident["evidence_reasons"][0]["signal_type"] == "new_session_context"


def test_incident_is_reachable_from_its_evidence_events(client):
    e1, _, e3 = _ingest_full_chain(client)

    from_e1 = client.get(f"/api/events/{e1['event_id']}/incidents").json()
    from_e3 = client.get(f"/api/events/{e3['event_id']}/incidents").json()
    assert len(from_e1) == 1
    assert from_e1[0]["incident_id"] == from_e3[0]["incident_id"]


def test_get_unknown_incident_returns_404(client):
    resp = client.get("/api/incidents/does-not-exist")
    assert resp.status_code == 404


def test_patch_incident_disposition(client):
    _ingest_full_chain(client)
    incident_id = client.get(
        "/api/incidents", params={"identity_id": "mallory@example.test"}
    ).json()[0]["incident_id"]

    resp = client.patch(
        f"/api/incidents/{incident_id}",
        json={"status": "investigating", "analyst_disposition": "true_positive", "notes": "checking with mallory"},
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["status"] == "investigating"
    assert updated["analyst_disposition"] == "true_positive"
    assert updated["notes"] == "checking with mallory"


def test_patch_incident_rejects_unknown_status(client):
    _ingest_full_chain(client)
    incident_id = client.get(
        "/api/incidents", params={"identity_id": "mallory@example.test"}
    ).json()[0]["incident_id"]

    resp = client.patch(f"/api/incidents/{incident_id}", json={"status": "not_a_real_status"})
    assert resp.status_code == 422


def test_replaying_the_chain_preserves_analyst_disposition(client):
    """Re-correlation must never silently reset an analyst's triage."""
    e1, e2, e3 = _ingest_full_chain(client)
    incident_id = client.get(
        "/api/incidents", params={"identity_id": "mallory@example.test"}
    ).json()[0]["incident_id"]

    client.patch(
        f"/api/incidents/{incident_id}",
        json={"status": "resolved", "analyst_disposition": "benign", "notes": "false alarm"},
    )

    # Replay the last event in the chain (same event_id) - re-triggers
    # correlation for this identity.
    client.post(
        "/api/events",
        json={
            "event_id": e3["event_id"],
            "timestamp": "2026-09-09T09:10:00Z",
            "source": "synthetic",
            "event_type": "file_access",
            "action": "read",
            "result": "success",
            "actor_id": "mallory@example.test",
            "actor_type": "user",
            "resource_type": "mailbox",
        },
    )

    incident = client.get(f"/api/incidents/{incident_id}").json()
    assert incident["status"] == "resolved"
    assert incident["analyst_disposition"] == "benign"
    assert incident["notes"] == "false alarm"


def test_incident_dashboard_pages_render(client):
    _ingest_full_chain(client)
    incident_id = client.get(
        "/api/incidents", params={"identity_id": "mallory@example.test"}
    ).json()[0]["incident_id"]

    queue = client.get("/incidents")
    assert queue.status_code == 200
    assert "mallory@example.test" in queue.text

    detail = client.get(f"/incidents/{incident_id}")
    assert detail.status_code == 200
    assert "risky_oauth_consent" in detail.text
    assert "IDT-CORR-001" in detail.text
    assert "<svg" in detail.text  # the evidence graph actually rendered

    missing = client.get("/incidents/does-not-exist")
    assert missing.status_code == 404

    identity_page = client.get("/identities/mallory@example.test")
    assert identity_page.status_code == 200
    assert incident_id in identity_page.text


def test_incident_graph_api(client):
    _, e2, _ = _ingest_full_chain(client)
    incident_id = client.get(
        "/api/incidents", params={"identity_id": "mallory@example.test"}
    ).json()[0]["incident_id"]

    resp = client.get(f"/api/incidents/{incident_id}/graph")
    assert resp.status_code == 200
    graph = resp.json()

    node_ids = {n["id"] for n in graph["nodes"]}
    assert "identity:mallory@example.test" in node_ids
    assert f"incident:{incident_id}" in node_ids
    # the consent event's app should show up, labeled with its display name
    assert "app:app-999" in node_ids
    app_node = next(n for n in graph["nodes"] if n["id"] == "app:app-999")
    assert app_node["label"] == "EvilApp"

    relations = {e["relation"] for e in graph["edges"]}
    assert "TRIGGERED" in relations
    assert "EVIDENCE_FOR" in relations
    assert "CONSENTED_TO" in relations
    assert "GRANTED" in relations

    evidence_edges = [e for e in graph["edges"] if e["relation"] == "EVIDENCE_FOR"]
    assert len(evidence_edges) == 3  # one per evidence event


def test_incident_graph_for_unknown_incident_returns_404(client):
    resp = client.get("/api/incidents/does-not-exist/graph")
    assert resp.status_code == 404
