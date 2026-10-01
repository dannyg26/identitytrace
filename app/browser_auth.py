"""Authorization-code sign-in with PKCE; provider tokens never become browser cookies."""

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import jwt
import requests
from authlib.common.errors import AuthlibBaseError
from authlib.integrations.requests_client import OAuth2Session
from fastapi import APIRouter, HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.responses import JSONResponse, RedirectResponse

from app.models.access import BrowserSession
from app.models.db import SessionLocal
from app.models.operations import AuditRecord

router = APIRouter(prefix="/auth", tags=["sign-in"])
SESSION_COOKIE = "__Host-idt-session"
FLOW_COOKIE = "__Host-idt-flow"


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class BrowserAuth:
    def __init__(self, verifier):
        self.verifier = verifier
        self.client_id = os.environ["IDENTITYTRACE_OIDC_CLIENT_ID"]
        if self.client_id == verifier.audience:
            raise ValueError("Browser client and API require separate audiences")
        self.client_secret = Path(os.environ["IDENTITYTRACE_OIDC_CLIENT_SECRET_FILE"]).read_text().strip()
        secret = Path(os.environ["IDENTITYTRACE_SESSION_SECRET_FILE"]).read_text().strip()
        if len(secret) < 32 or not self.client_secret:
            raise ValueError("Browser sign-in requires a client secret and a session signing key of at least 32 characters")
        self.signer = URLSafeTimedSerializer(secret, salt="identitytrace-login-v1")
        self.base_url = os.environ["IDENTITYTRACE_PUBLIC_URL"].rstrip("/")
        self.authorize_url = os.environ["IDENTITYTRACE_OIDC_AUTHORIZE_URL"]
        self.token_url = os.environ["IDENTITYTRACE_OIDC_TOKEN_URL"]
        self.scope = os.environ["IDENTITYTRACE_OIDC_SCOPE"]
        self.subject_claim = os.environ.get("IDENTITYTRACE_OIDC_SUBJECT_CLAIM", "sub")
        for url in (self.base_url, self.authorize_url, self.token_url):
            parsed = urlsplit(url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
                raise ValueError("Browser sign-in URLs must use HTTPS without credentials, fragments or query parameters")
        if urlsplit(self.base_url).path:
            raise ValueError("PUBLIC_URL must be an HTTPS origin without a path")
        if "openid" not in self.scope.split():
            raise ValueError("Browser sign-in requires openid scope")
        self.redirect_uri = self.base_url + "/auth/callback"

    def client(self, state=None):
        return OAuth2Session(self.client_id, self.client_secret, scope=self.scope,
                             redirect_uri=self.redirect_uri, state=state,
                             token_endpoint_auth_method="client_secret_post", code_challenge_method="S256")

    def authenticate(self, cookie):
        from app.security import Principal
        if not cookie or len(cookie) > 128:
            return None
        with SessionLocal() as db:
            session = db.get(BrowserSession, token_hash(cookie))
            if (session and utc(session.expires_at) > datetime.now(timezone.utc)
                    and session.organization_id == self.verifier.organization
                    and session.issuer == self.verifier.issuer
                    and session.role in self.verifier.role_map.values()):
                return Principal(session.principal, session.role)
        return None


def configured(request):
    browser = request.app.state.access_policy.browser
    if browser is None:
        raise HTTPException(404, "Browser sign-in is not configured")
    if str(request.base_url).rstrip("/") != browser.base_url:
        raise HTTPException(400, "Sign-in must use the configured public HTTPS origin")
    return browser


@router.get("/login")
def login(request: Request):
    browser = configured(request)
    verifier, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    with browser.client() as client:
        url, state = client.create_authorization_url(browser.authorize_url, code_verifier=verifier, nonce=nonce)
    response = RedirectResponse(url, status_code=303)
    response.set_cookie(FLOW_COOKIE, browser.signer.dumps({"state": state, "verifier": verifier, "nonce": nonce}),
                        max_age=300, httponly=True, secure=True, samesite="lax", path="/")
    return response


@router.get("/callback")
def callback(request: Request):
    browser = configured(request)
    try:
        flow = browser.signer.loads(request.cookies.get(FLOW_COOKIE, ""), max_age=300)
        state = request.query_params.get("state", "")
        if not state or not hmac.compare_digest(state, flow["state"]):
            raise ValueError("state mismatch")
        with browser.client(state=flow["state"]) as client:
            tokens = client.fetch_token(browser.token_url, authorization_response=str(request.url),
                                         code_verifier=flow["verifier"], timeout=10)
        identity = browser.verifier.decode(tokens["id_token"], audience=browser.client_id)
        access = browser.verifier.decode(tokens["access_token"])
        audiences = identity["aud"]
        if ((isinstance(audiences, list) and len(audiences) > 1 and not identity.get("azp"))
                or ("azp" in identity and identity["azp"] != browser.client_id)):
            raise ValueError("ID token authorized party mismatch")
        if (not hmac.compare_digest(str(identity.get("nonce", "")), flow["nonce"])
                or not identity.get(browser.subject_claim)
                or identity[browser.subject_claim] != access.get(browser.subject_claim)):
            raise ValueError("nonce or subject mismatch")
        principal = browser.verifier.principal(access)
        if principal is None or principal.role == "ingestor":
            raise ValueError("No browser role assigned")
        expiry = min(datetime.fromtimestamp(access["exp"], timezone.utc),
                     datetime.fromtimestamp(identity["exp"], timezone.utc),
                     datetime.now(timezone.utc) + timedelta(minutes=15))
        session_token = secrets.token_urlsafe(32)
        with SessionLocal() as db:
            # Expired sessions are removed on successful login; no refresh token is retained.
            db.query(BrowserSession).filter(BrowserSession.expires_at <= datetime.now(timezone.utc)).delete()
            old = request.cookies.get(SESSION_COOKIE)
            if old:
                db.query(BrowserSession).filter_by(token_hash=token_hash(old)).delete()
            db.add(BrowserSession(token_hash=token_hash(session_token), principal=principal.name,
                                  role=principal.role, organization_id=browser.verifier.organization,
                                  issuer=browser.verifier.issuer, expires_at=expiry))
            db.add(AuditRecord(principal=principal.name, action="session.created", entity_id="browser"))
            db.commit()
        response = RedirectResponse("/incidents", status_code=303)
        response.set_cookie(SESSION_COOKIE, session_token, max_age=max(1, int((expiry - datetime.now(timezone.utc)).total_seconds())),
                            httponly=True, secure=True, samesite="lax", path="/")
        response.delete_cookie(FLOW_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        return response
    except (BadSignature, ValueError, TypeError, KeyError, jwt.PyJWTError, AuthlibBaseError, requests.RequestException):
        response = JSONResponse({"detail": "Sign-in failed. Start a new sign-in attempt."}, status_code=401)
        response.delete_cookie(FLOW_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        return response


@router.post("/logout")
def logout(request: Request):
    with SessionLocal() as db:
        db.query(BrowserSession).filter_by(token_hash=token_hash(request.cookies.get(SESSION_COOKIE, ""))).delete()
        db.add(AuditRecord(principal=request.state.principal.name, action="session.ended", entity_id="browser"))
        db.commit()
    response = JSONResponse({"status": "signed_out"})
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return response
