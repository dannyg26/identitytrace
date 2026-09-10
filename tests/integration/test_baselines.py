"""Integration tests for the Phase 3 exit criterion: the identity profile
exposes a baseline and its deviations, built from real ingestion traffic.
"""


def _post_normal_event(client, timestamp):
    return client.post(
        "/api/events",
        json={
            "timestamp": timestamp,
            "source": "synthetic",
            "event_type": "signin",
            "action": "login",
            "result": "success",
            "actor_id": "carol@example.test",
            "actor_type": "user",
            "device_id": "d1",
            "ip_address": "1.1.1.1",
            "geo_country": "US",
            "app_id": "app-1",
            "auth_protocol": "interactive",
        },
    )


def test_no_deviations_until_baseline_is_established(client):
    # First 3 events: too little history to call anything "new" yet.
    for day in (1, 2, 3):
        resp = _post_normal_event(client, f"2026-09-0{day}T09:00:00Z")
        event_id = resp.json()["event_id"]
        deviations = client.get(f"/api/events/{event_id}/deviations").json()
        assert deviations == []

    # 4th event, still matching the now-established baseline exactly.
    resp = _post_normal_event(client, "2026-09-04T09:00:00Z")
    event_id = resp.json()["event_id"]
    assert client.get(f"/api/events/{event_id}/deviations").json() == []


def test_new_device_is_flagged_once_baseline_exists(client):
    for day in (1, 2, 3, 4):
        _post_normal_event(client, f"2026-09-0{day}T09:00:00Z")

    resp = client.post(
        "/api/events",
        json={
            "timestamp": "2026-09-05T09:00:00Z",
            "source": "synthetic",
            "event_type": "signin",
            "action": "login",
            "result": "success",
            "actor_id": "carol@example.test",
            "actor_type": "user",
            "device_id": "d-new",  # the only thing that changed
            "ip_address": "1.1.1.1",
            "geo_country": "US",
            "app_id": "app-1",
            "auth_protocol": "interactive",
        },
    )
    event_id = resp.json()["event_id"]

    deviations = client.get(f"/api/events/{event_id}/deviations").json()
    assert len(deviations) == 1
    assert deviations[0]["deviation_type"] == "new_device"
    assert deviations[0]["weight"] == 15
    assert "d-new" in deviations[0]["reason"]


def test_replaying_the_same_event_does_not_duplicate_deviations(client):
    for day in (1, 2, 3, 4):
        _post_normal_event(client, f"2026-09-0{day}T09:00:00Z")

    payload = {
        "timestamp": "2026-09-05T09:00:00Z",
        "source": "synthetic",
        "event_type": "signin",
        "action": "login",
        "result": "success",
        "actor_id": "carol@example.test",
        "actor_type": "user",
        "device_id": "d-new",
        "ip_address": "1.1.1.1",
        "geo_country": "US",
        "app_id": "app-1",
        "auth_protocol": "interactive",
    }
    first = client.post("/api/events", json=payload)
    event_id = first.json()["event_id"]
    # Replay: same event_id this time, same fields.
    client.post("/api/events", json={**payload, "event_id": event_id})

    deviations = client.get(f"/api/events/{event_id}/deviations").json()
    assert len(deviations) == 1


def test_identity_profile_api_reflects_baseline_and_history(client):
    for day in (1, 2, 3, 4):
        _post_normal_event(client, f"2026-09-0{day}T09:00:00Z")

    resp = client.get("/api/identities/carol@example.test")
    assert resp.status_code == 200
    data = resp.json()
    assert data["profile"]["event_count"] == 4
    assert data["profile"]["known_devices"] == ["d1"]
    assert data["profile"]["known_ips"] == ["1.1.1.1"]
    assert len(data["recent_events"]) == 4

    listing = client.get("/api/identities").json()
    assert any(i["actor_id"] == "carol@example.test" and i["event_count"] == 4 for i in listing)


def test_unknown_identity_returns_404(client):
    resp = client.get("/api/identities/nobody@example.test")
    assert resp.status_code == 404


def test_identity_dashboard_pages_render(client):
    for day in (1, 2, 3, 4):
        _post_normal_event(client, f"2026-09-0{day}T09:00:00Z")
    client.post(
        "/api/events",
        json={
            "timestamp": "2026-09-05T09:00:00Z",
            "source": "synthetic",
            "event_type": "signin",
            "action": "login",
            "result": "success",
            "actor_id": "carol@example.test",
            "actor_type": "user",
            "device_id": "d-new",
            "ip_address": "1.1.1.1",
            "geo_country": "US",
            "app_id": "app-1",
            "auth_protocol": "interactive",
        },
    )

    listing_page = client.get("/identities")
    assert listing_page.status_code == 200
    assert "carol@example.test" in listing_page.text

    detail_page = client.get("/identities/carol@example.test")
    assert detail_page.status_code == 200
    assert "new_device" in detail_page.text
    assert "d1" in detail_page.text

    missing_page = client.get("/identities/nobody@example.test")
    assert missing_page.status_code == 404
