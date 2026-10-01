import hashlib
import json

import pytest

from app.security import AccessPolicy, hash_password, verify_password
from tests.integration.test_ingestion_reliability import _chain


@pytest.fixture()
def secured(client, monkeypatch, tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps([
        {"name": role, "role": role, "token_hash": hashlib.sha256(role.encode()).hexdigest(),
         "password_hash": hash_password("test-password-12345") if role == "admin" else ""}
        for role in ("admin", "viewer", "analyst", "ingestor")
    ]))
    monkeypatch.delenv("IDENTITYTRACE_DEMO_MODE")
    monkeypatch.setenv("IDENTITYTRACE_CREDENTIALS_FILE", str(path))
    client.app.state.access_policy = AccessPolicy()
    return client


@pytest.mark.parametrize("path", ["/", "/api/events", "/api/incidents", "/docs", "/openapi.json"])
def test_every_sensitive_surface_requires_authentication(secured, path):
    assert secured.get(path).status_code == 401
    assert secured.get("/health").status_code == 200


def test_browser_basic_auth_and_password_hashes(secured):
    assert secured.get("/", auth=("admin", "test-password-12345")).status_code == 200
    assert secured.get("/", auth=("admin", "wrong")).status_code == 401
    assert not verify_password("password", "malformed")
    assert secured.get("/", headers={"Authorization": "Basic invalid!"}).status_code == 401
    response = secured.get("/", headers={"Authorization": "Bearer viewer"})
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_ingestor_cannot_read_evidence_or_run_evaluation(secured):
    secured.headers["Authorization"] = "Bearer ingestor"
    assert secured.post("/api/events", json=_chain()[0]).status_code == 201
    assert secured.get("/api/events").status_code == 403
    assert secured.post("/api/evaluation/run", json={}).status_code == 403


def test_viewer_cannot_change_evidence_or_triage(secured):
    secured.headers["Authorization"] = "Bearer viewer"
    assert secured.get("/api/events").status_code == 200
    assert secured.post("/api/events", json=_chain()[0]).status_code == 403
    assert secured.patch("/api/incidents/example", json={"status": "resolved"}).status_code == 403
    assert secured.get("/evaluation").status_code == 403
    assert secured.get("/api/audit").status_code == 403


def test_analyst_disposition_is_audited_and_admin_only_history(secured):
    secured.headers["Authorization"] = "Bearer admin"
    for event in _chain():
        secured.post("/api/events", json=event)
    incident = secured.get("/api/incidents").json()[0]
    secured.headers["Authorization"] = "Bearer analyst"
    assert secured.patch(f'/api/incidents/{incident["incident_id"]}', json={"notes": "reviewed"}).status_code == 200
    assert secured.post("/api/identity-links", json={"source": "github", "alias": "a", "canonical_id": "alice"}).status_code == 403
    secured.headers["Authorization"] = "Bearer admin"
    audit = secured.get("/api/audit").json()[0]
    assert audit["principal"] == "analyst"
    assert audit["before"]["notes"] is None
    assert audit["after"]["notes"] == "reviewed"


def test_cross_origin_and_form_writes_are_rejected(secured):
    secured.headers["Authorization"] = "Bearer admin"
    assert secured.post("/api/events", json=_chain()[0], headers={"Origin": "https://evil.test"}).status_code == 403
    assert secured.post("/api/events", data={"actor_id": "alice"}).status_code == 415
    assert secured.post("/api/events", json=_chain()[0], headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_missing_configuration_fails_closed(client, monkeypatch):
    monkeypatch.delenv("IDENTITYTRACE_DEMO_MODE")
    monkeypatch.delenv("IDENTITYTRACE_CREDENTIALS_FILE", raising=False)
    client.app.state.access_policy = AccessPolicy()
    assert client.get("/api/events").status_code == 503


@pytest.mark.parametrize("data", [{}, [{"name": "a", "role": "root"}],
                                  [{"name": "a", "role": "admin"}]])
def test_invalid_credential_configuration_rejected(monkeypatch, tmp_path, data):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(data))
    monkeypatch.setenv("IDENTITYTRACE_CREDENTIALS_FILE", str(path))
    with pytest.raises(ValueError):
        AccessPolicy()
