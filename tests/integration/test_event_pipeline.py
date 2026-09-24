"""Integration tests for the Phase 1 + Phase 2 exit criteria:

- events can be ingested, queried, replayed, and traced back to raw evidence
  (Phase 1), and
- every ingested event is run through the loaded atomic detection rules and
  the resulting matches are persisted and queryable (Phase 2).
"""

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_m365_source_flows_through_the_full_pipeline(client):
    """Phase 6 exit criterion: a third telemetry domain, normalized and
    detected exactly like the first two - no special-casing required."""
    rule_resp = client.post(
        "/api/events",
        json={
            "source": "m365",
            "raw": {
                "Id": "m365-int-1",
                "CreationTime": "2026-09-09T09:15:00Z",
                "Operation": "New-InboxRule",
                "Workload": "Exchange",
                "UserId": "dave@example.test",
                "ResultStatus": "Succeeded",
            },
        },
    )
    assert rule_resp.status_code == 201, rule_resp.text
    rule_event = rule_resp.json()
    assert rule_event["source"] == "m365"

    matches = client.get(f"/api/events/{rule_event['event_id']}/matches").json()
    # IDT-M365-001 (the mailbox-rule-specific rule) fires, and so does the
    # source-agnostic IDT-XDOMAIN-002 (any successful mailbox/secret/role
    # access) - the event is tagged resource_type="mailbox" regardless of
    # which specific operation touched it, so both rules independently see
    # evidence here. Two complementary detections on one event, not a bug.
    assert {m["rule_id"] for m in matches} == {"IDT-M365-001", "IDT-XDOMAIN-002"}

    # The source-agnostic bulk-transfer rule from Phase 2 (IDT-XDOMAIN-001)
    # should apply to m365 telemetry with zero m365-specific code - exactly
    # the point of normalizing everything into one schema first.
    bulk_resp = client.post(
        "/api/events",
        json={
            "source": "m365",
            "raw": {
                "Id": "m365-int-2",
                "CreationTime": "2026-09-09T09:20:00Z",
                "Operation": "FileDownloaded",
                "Workload": "SharePoint",
                "UserId": "dave@example.test",
                "ClientIP": "203.0.113.60",
                "ObjectId": "https://contoso.sharepoint.com/sites/finance/all_customers.xlsx",
                "ResultStatus": "Succeeded",
                "SizeInBytes": 500_000_000,
            },
        },
    )
    bulk_event = bulk_resp.json()
    bulk_matches = client.get(f"/api/events/{bulk_event['event_id']}/matches").json()
    assert "IDT-XDOMAIN-001" in {m["rule_id"] for m in bulk_matches}


def test_ingest_query_trace_and_detect(client):
    entra_raw = {
        "id": "signin-1",
        "createdDateTime": "2026-09-09T17:02:11Z",
        "userPrincipalName": "alice@example.test",
        "appId": "app-123",
        "ipAddress": "203.0.113.25",
        "location": {"countryOrRegion": "US"},
        "deviceDetail": {"deviceId": "device-1", "browser": "Chrome 120"},
        "status": {"errorCode": 0},
        "clientAppUsed": "Mobile Apps and Desktop clients",  # real shape - authenticationProtocol is never populated
        "sessionId": "sess-1",
    }
    github_raw = {
        "action": "git.clone",
        "actor": "alice",
        "actor_ip": "203.0.113.25",
        "repo": "acme/secret-repo",
        "token_id": "pat-1",
        "token_scopes": ["repo"],
        "created_at": 1757430131000,
    }
    already_normalized = {
        "timestamp": "2026-09-09T17:08:15Z",
        "source": "synthetic",
        "event_type": "file_download",
        "action": "download",
        "result": "success",
        "actor_id": "alice@example.test",
        "actor_type": "user",
        "bytes_transferred": 500_000_000,
    }

    r1 = client.post("/api/events", json={"source": "entra", "raw": entra_raw})
    assert r1.status_code == 201, r1.text
    entra_event = r1.json()
    assert entra_event["source"] == "entra"
    assert entra_event["event_type"] == "signin"
    assert entra_event["raw_event_ref"] == entra_raw  # evidence preserved verbatim

    r2 = client.post("/api/events", json={"source": "github", "raw": github_raw})
    assert r2.status_code == 201, r2.text
    github_event = r2.json()
    assert github_event["source"] == "github"
    assert github_event["actor_type"] == "token"

    r3 = client.post("/api/events", json=already_normalized)
    assert r3.status_code == 201, r3.text
    synthetic_event = r3.json()

    # queryable
    all_events = client.get("/api/events").json()
    assert len(all_events) == 3

    entra_only = client.get("/api/events", params={"source": "entra"}).json()
    assert len(entra_only) == 1
    assert entra_only[0]["event_id"] == entra_event["event_id"]

    alice_events = client.get("/api/events", params={"actor_id": "alice@example.test"}).json()
    # github's actor_id is the GitHub username ("alice"), not alice's email -
    # only the entra and synthetic events match this filter.
    assert len(alice_events) == 2

    # traceable to raw evidence
    fetched = client.get(f"/api/events/{github_event['event_id']}").json()
    assert fetched["raw_event_ref"] == github_raw

    fetched_synthetic = client.get(f"/api/events/{synthetic_event['event_id']}").json()
    assert fetched_synthetic["bytes_transferred"] == 500_000_000

    # detections fired during ingestion, per event
    entra_matches = client.get(f"/api/events/{entra_event['event_id']}/matches").json()
    assert {m["rule_id"] for m in entra_matches} == {"IDT-ENTRA-003"}  # device-code login

    github_matches = client.get(f"/api/events/{github_event['event_id']}/matches").json()
    # PAT-driven clone of a repo with "secret" in its name -> two rules fire
    assert {m["rule_id"] for m in github_matches} == {"IDT-GITHUB-001", "IDT-GITHUB-003"}

    synthetic_matches = client.get(f"/api/events/{synthetic_event['event_id']}/matches").json()
    assert {m["rule_id"] for m in synthetic_matches} == {"IDT-XDOMAIN-001"}  # bulk transfer

    # detections are also queryable in aggregate
    all_matches = client.get("/api/matches").json()
    assert len(all_matches) == 4  # 1 + 2 + 1 from above
    high_severity = client.get("/api/matches", params={"severity": "high"}).json()
    assert {m["rule_id"] for m in high_severity} == {"IDT-GITHUB-003", "IDT-XDOMAIN-001"}


def test_replaying_the_same_event_does_not_duplicate_matches(client):
    raw = {
        "id": "signin-replay",
        "createdDateTime": "2026-09-09T17:02:11Z",
        "userPrincipalName": "bob@example.test",
        "appId": "app-1",
        "status": {"errorCode": 0},
        "clientAppUsed": "Mobile Apps and Desktop clients",  # real shape - authenticationProtocol is never populated
    }
    payload = {"source": "entra", "raw": raw}

    client.post("/api/events", json=payload)
    client.post("/api/events", json=payload)  # replay

    matches = client.get("/api/matches", params={"actor_id": "bob@example.test"}).json()
    assert len(matches) == 1


def test_unknown_source_is_rejected(client):
    resp = client.post("/api/events", json={"source": "not_a_source", "raw": {}})
    assert resp.status_code == 400


def test_missing_required_field_returns_422(client):
    resp = client.post("/api/events", json={"source": "entra", "raw": {"id": "x"}})
    assert resp.status_code == 422


def test_get_unknown_event_returns_404(client):
    resp = client.get("/api/events/does-not-exist")
    assert resp.status_code == 404


def test_get_matches_for_unknown_event_returns_404(client):
    resp = client.get("/api/events/does-not-exist/matches")
    assert resp.status_code == 404


def test_get_unknown_match_returns_404(client):
    resp = client.get("/api/matches/does-not-exist")
    assert resp.status_code == 404


def test_detection_library_is_listed(client):
    resp = client.get("/api/detections")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 14
    ids = {r["id"] for r in rules}
    assert "IDT-ENTRA-001" in ids
    assert all(r["last_triggered"] is None for r in rules)  # nothing ingested yet


def test_dashboard_pages_render(client):
    client.post(
        "/api/events",
        json={
            "timestamp": "2026-09-09T17:08:15Z",
            "source": "synthetic",
            "event_type": "file_download",
            "action": "download",
            "result": "success",
            "actor_id": "alice@example.test",
            "actor_type": "user",
            "bytes_transferred": 500_000_000,
        },
    )

    overview = client.get("/")
    assert overview.status_code == 200
    assert "alice@example.test" in overview.text
    assert "IDT-XDOMAIN-001" in overview.text  # recent detections section

    events_page = client.get("/events")
    assert events_page.status_code == 200
    assert "alice@example.test" in events_page.text
    assert "IDT-XDOMAIN-001" in events_page.text  # per-event detections column

    filtered = client.get("/events", params={"source": "synthetic"})
    assert filtered.status_code == 200

    rules_page = client.get("/rules")
    assert rules_page.status_code == 200
    assert "IDT-ENTRA-001" in rules_page.text


def test_evaluation_api_and_dashboard(client):
    resp = client.post("/api/evaluation/run", json={"seed": 1, "scenarios_per_type": 1})
    assert resp.status_code == 200
    metrics = resp.json()
    assert metrics["totals"]["attack_scenarios"] == 6  # 1 per attack type
    assert "isolated_rule_baseline" in metrics
    assert "correlation_engine" in metrics

    # a live evaluation run must never touch the app's own live database
    live_events_before = client.get("/api/events").json()

    page = client.get("/evaluation", params={"seed": 1, "scenarios_per_type": 1})
    assert page.status_code == 200
    assert "Isolated rules vs" in page.text
    assert "A1" in page.text

    live_events_after = client.get("/api/events").json()
    assert live_events_before == live_events_after


def test_alerts_api_and_dashboard(client):
    # IDT-XDOMAIN-001 (bulk transfer) is "high" severity - qualifies as an alert.
    high_sev = client.post(
        "/api/events",
        json={
            "timestamp": "2026-09-09T09:00:00Z",
            "source": "synthetic",
            "event_type": "file_download",
            "action": "download",
            "result": "success",
            "actor_id": "alerts-test@example.test",
            "actor_type": "user",
            "bytes_transferred": 500_000_000,
        },
    )
    assert high_sev.status_code == 201

    # IDT-ENTRA-003 (device-code signin) is "low" severity - must NOT
    # appear in /alerts even though it's a real, correctly-fired match.
    low_sev = client.post(
        "/api/events",
        json={
            "source": "entra",
            "raw": {
                "id": "alerts-low-sev",
                "createdDateTime": "2026-09-09T09:05:00Z",
                "userPrincipalName": "alerts-test@example.test",
                "status": {"errorCode": 0},
                "clientAppUsed": "Mobile Apps and Desktop clients",  # real shape - authenticationProtocol is never populated
            },
        },
    )
    assert low_sev.status_code == 201

    alerts = client.get("/api/alerts").json()
    rule_ids = {a["rule_id"] for a in alerts}
    assert "IDT-XDOMAIN-001" in rule_ids
    assert "IDT-ENTRA-003" not in rule_ids
    assert all(a["severity"] in ("high", "critical") for a in alerts)

    filtered = client.get("/api/alerts", params={"actor_id": "alerts-test@example.test"}).json()
    assert len(filtered) == 1

    page = client.get("/alerts")
    assert page.status_code == 200
    assert "IDT-XDOMAIN-001" in page.text
    assert "IDT-ENTRA-003" not in page.text
