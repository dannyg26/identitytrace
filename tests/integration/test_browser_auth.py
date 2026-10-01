import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from app.browser_auth import FLOW_COOKIE, SESSION_COOKIE, BrowserAuth
from app.models.access import BrowserSession
from app.models.db import SessionLocal, bind_organization, verify_schema
from tests.integration.test_production_features import oidc as external_oidc  # noqa: F401


@pytest.fixture()
def browser(request, monkeypatch, tmp_path):
    client, sign, policy = request.getfixturevalue("external_oidc")
    secret_file = tmp_path / "client-secret.txt"
    secret_file.write_text("client-secret-for-isolated-tests")
    session_file = tmp_path / "session-secret.txt"
    session_file.write_text("s" * 64)
    for name, value in {
        "IDENTITYTRACE_OIDC_CLIENT_ID": "browser-client",
        "IDENTITYTRACE_OIDC_CLIENT_SECRET_FILE": str(secret_file),
        "IDENTITYTRACE_SESSION_SECRET_FILE": str(session_file),
        "IDENTITYTRACE_PUBLIC_URL": "https://testserver",
        "IDENTITYTRACE_OIDC_AUTHORIZE_URL": "https://identity.example.test/authorize",
        "IDENTITYTRACE_OIDC_TOKEN_URL": "https://identity.example.test/token",
        "IDENTITYTRACE_OIDC_SCOPE": "openid identitytrace/read",
    }.items():
        monkeypatch.setenv(name, value)
    policy.browser = BrowserAuth(policy.oidc)
    return client, sign, policy.browser


def prepare(browser, monkeypatch, *, nonce_override=None, id_subject=None, role="IT.Viewer"):
    client, sign, config = browser
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 303
    params = parse_qs(urlsplit(response.headers["location"]).query)
    assert params["code_challenge_method"] == ["S256"]
    assert "code_challenge" in params
    assert "client_secret" not in params
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    flow = config.signer.loads(client.cookies.get(FLOW_COOKIE))
    tokens = {"id_token": sign(aud="browser-client", nonce=nonce_override or flow["nonce"],
                               sub=id_subject or "person-one"),
              "access_token": sign(roles=[role])}
    monkeypatch.setattr("app.browser_auth.OAuth2Session.fetch_token", lambda *a, **kw: tokens)
    return client, flow


def test_browser_login_session_logout_and_audit(browser, monkeypatch):
    client, flow = prepare(browser, monkeypatch)
    response = client.get("/auth/callback", params={"code": "one-time-code", "state": flow["state"]}, follow_redirects=False)
    assert response.status_code == 303
    cookie = client.cookies.get(SESSION_COOKIE)
    assert cookie and "access_token" not in response.headers["set-cookie"]
    with SessionLocal() as db:
        session = db.query(BrowserSession).one()
        assert session.token_hash == hashlib.sha256(cookie.encode()).hexdigest()
        assert session.token_hash != cookie
    assert client.get("/incidents").status_code == 200
    assert client.get("/api/audit").status_code == 403
    assert client.post("/auth/logout", json={}).status_code == 200
    assert client.get("/api/events").status_code == 401
    client.cookies.set(SESSION_COOKIE, cookie)
    assert client.get("/api/events").status_code == 401


@pytest.mark.parametrize("change", [{"nonce_override": "wrong"}, {"id_subject": "another-person"}, {"role": "unassigned"}])
def test_nonce_subject_and_role_rejected(browser, monkeypatch, change):
    client, flow = prepare(browser, monkeypatch, **change)
    response = client.get("/auth/callback", params={"code": "code", "state": flow["state"]})
    assert response.status_code == 401
    assert not client.cookies.get(SESSION_COOKIE)


def test_state_tampering_and_missing_cookie_fail_before_token_exchange(browser, monkeypatch):
    client, flow = prepare(browser, monkeypatch)
    def forbidden(*args, **kwargs):
        pytest.fail("State validation must precede token exchange")
    monkeypatch.setattr("app.browser_auth.OAuth2Session.fetch_token", forbidden)
    assert client.get("/auth/callback?code=x&state=wrong").status_code == 401
    client.cookies.clear()
    assert client.get("/auth/callback", params={"code": "x", "state": flow["state"]}).status_code == 401


def test_session_expiry_and_cross_origin_write(browser, monkeypatch):
    client, flow = prepare(browser, monkeypatch)
    assert client.get("/auth/callback", params={"code": "x", "state": flow["state"]}, follow_redirects=False).status_code == 303
    assert client.post("/auth/logout", json={}, headers={"Origin": "https://evil.test"}).status_code == 403
    with SessionLocal() as db:
        db.query(BrowserSession).one().expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    assert client.get("/api/events").status_code == 401


def test_https_and_configured_host_are_required(browser):
    client, _, _ = browser
    assert client.get("http://testserver/api/events").status_code == 426
    assert client.get("https://evil.test/auth/login").status_code == 400
    response = client.get("/incidents", headers={"Accept": "text/html"}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/auth/login"


def test_database_cannot_be_reassigned(client):
    bind_organization("first-org")
    bind_organization("first-org")
    verify_schema("first-org")
    with pytest.raises(RuntimeError, match="different organization"):
        verify_schema("second-org")
    with pytest.raises(RuntimeError, match="reassign"):
        bind_organization("second-org")


@pytest.mark.parametrize("claims", [
    {"aud": ["browser-client", "another-client"]},
    {"azp": "another-client"},
])
def test_id_token_authorized_party_is_enforced(browser, monkeypatch, claims):
    client, flow = prepare(browser, monkeypatch)
    _, sign, _ = browser
    tokens = {"id_token": sign(**{"aud": "browser-client", "nonce": flow["nonce"], **claims}),
              "access_token": sign()}
    monkeypatch.setattr("app.browser_auth.OAuth2Session.fetch_token", lambda *a, **kw: tokens)
    assert client.get("/auth/callback", params={"code": "x", "state": flow["state"]}).status_code == 401


def test_entra_object_id_links_pairwise_subjects(browser, monkeypatch):
    client, flow = prepare(browser, monkeypatch)
    _, sign, config = browser
    config.subject_claim = "oid"
    tokens = {"id_token": sign(aud="browser-client", nonce=flow["nonce"], sub="web-pairwise-subject", oid="same-object"),
              "access_token": sign(sub="api-pairwise-subject", oid="same-object")}
    monkeypatch.setattr("app.browser_auth.OAuth2Session.fetch_token", lambda *a, **kw: tokens)
    assert client.get("/auth/callback", params={"code": "x", "state": flow["state"]}, follow_redirects=False).status_code == 303


def test_same_browser_and_api_audience_is_rejected(browser, monkeypatch):
    _, _, config = browser
    monkeypatch.setenv("IDENTITYTRACE_OIDC_CLIENT_ID", config.verifier.audience)
    with pytest.raises(ValueError, match="separate audiences"):
        BrowserAuth(config.verifier)
