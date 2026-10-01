"""File-backed credentials for a single-organization deployment.

No default credentials. Browser users authenticate with HTTP Basic; collectors
can use bearer tokens. Serve behind TLS when accessed beyond loopback.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, RedirectResponse

ROLES = {"viewer", "analyst", "ingestor", "admin"}


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
    return f"scrypt${salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt, _ = encoded.split("$")
        return algorithm == "scrypt" and hmac.compare_digest(hash_password(password, salt), encoded)
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class Principal:
    name: str
    role: str


class AccessPolicy:
    def __init__(self):
        self.demo = os.environ.get("IDENTITYTRACE_DEMO_MODE") == "1"
        self.production = os.environ.get("IDENTITYTRACE_ENV") == "production"
        from app.oidc import OIDCVerifier
        self.oidc = OIDCVerifier() if os.environ.get("IDENTITYTRACE_OIDC_ISSUER") else None
        from app.browser_auth import BrowserAuth
        self.browser = BrowserAuth(self.oidc) if self.oidc and os.environ.get("IDENTITYTRACE_OIDC_CLIENT_ID") else None
        if self.production and (self.demo or self.oidc is None):
            raise ValueError("Production requires organization-scoped OIDC and forbids demo mode")
        path = os.environ.get("IDENTITYTRACE_CREDENTIALS_FILE")
        self.users = json.loads(Path(path).read_text(encoding="utf-8")) if path else []
        self.failures = {}
        if not isinstance(self.users, list):
            raise ValueError("credentials file must contain a list")
        names = set()
        for user in self.users:
            if not isinstance(user, dict) or not user.get("name") or user.get("role") not in ROLES:
                raise ValueError("each credential requires a name and valid role")
            if user["name"] in names or not (user.get("password_hash") or user.get("token_hash")):
                raise ValueError("credential names must be unique and have a password or token hash")
            names.add(user["name"])

    def authenticate(self, authorization: str) -> Principal | None:
        if len(authorization) > 16384:
            return None
        scheme, _, value = authorization.partition(" ")
        if self.production:
            return self.oidc.verify(value) if scheme.lower() == "bearer" else None
        if scheme.lower() == "basic":
            try:
                name, password = base64.b64decode(value, validate=True).decode().split(":", 1)
            except (ValueError, UnicodeError):
                return None
            for user in self.users:
                if user["name"] == name and verify_password(password, user.get("password_hash", "")):
                    return Principal(name, user["role"])
        elif scheme.lower() == "bearer":
            digest = hashlib.sha256(value.encode()).hexdigest()
            for user in self.users:
                if hmac.compare_digest(digest, user.get("token_hash", "")):
                    return Principal(user["name"], user["role"])
            if self.oidc:
                return self.oidc.verify(value)
        return None


def permitted(principal: Principal, method: str, path: str) -> bool:
    if path == "/auth/logout":
        return method == "POST"
    if principal.role == "admin":
        return True
    if path.startswith("/api/audit") or path.startswith("/api/identity-links"):
        return False
    if path == "/metrics":
        return False
    if principal.role == "ingestor":
        return method == "POST" and path == "/api/events"
    if path in {"/evaluation", "/api/evaluation/run"}:
        return principal.role == "analyst"
    if method in {"GET", "HEAD"}:
        return True
    return principal.role == "analyst" and method == "PATCH" and path.startswith("/api/incidents/")


class AccessMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path in {"/health", "/ready"}:
            return await call_next(request)
        policy = request.app.state.access_policy
        if policy.production and request.url.scheme != "https":
            return JSONResponse({"detail": "HTTPS is required"}, status_code=426)
        if request.url.path in {"/auth/login", "/auth/callback"}:
            return await call_next(request)
        host = request.client.host if request.client else ""
        if policy.demo:
            if (host not in {"127.0.0.1", "::1", "testclient"}
                    or request.url.hostname not in {"localhost", "127.0.0.1", "::1", "testserver"}):
                return JSONResponse({"detail": "Demo mode only accepts loopback clients"}, status_code=403)
            principal = Principal("local-demo", "admin")
        else:
            if not policy.users and policy.oidc is None:
                return JSONResponse({"detail": "Configure IDENTITYTRACE_CREDENTIALS_FILE before use"}, status_code=503)
            now = time.monotonic()
            policy.failures = {key: value for key, value in policy.failures.items() if now - value[0] < 60}
            failed_at, count = policy.failures.get(host, (now, 0))
            if count >= 10:
                return JSONResponse({"detail": "Too many authentication failures"}, status_code=429,
                                    headers={"Retry-After": "60"})
            authorization = request.headers.get("authorization", "")
            principal = await run_in_threadpool(policy.authenticate, authorization)
            if principal is None and not authorization and policy.browser:
                from app.browser_auth import SESSION_COOKIE
                principal = await run_in_threadpool(policy.browser.authenticate, request.cookies.get(SESSION_COOKIE))
            if principal is None:
                if (policy.browser and not authorization and request.method == "GET"
                        and "text/html" in request.headers.get("accept", "")
                        and not request.url.path.startswith("/api/")):
                    return RedirectResponse("/auth/login", status_code=303)
                if len(policy.failures) < 4096 or host in policy.failures:
                    policy.failures[host] = (failed_at, count + 1)
                return JSONResponse({"detail": "Authentication required"}, status_code=401,
                                    headers={"WWW-Authenticate": 'Basic realm="IdentityTrace", charset="UTF-8"'})
            policy.failures.pop(host, None)
        if not permitted(principal, request.method, request.url.path):
            return JSONResponse({"detail": "Insufficient permission"}, status_code=403)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            if (request.headers.get("sec-fetch-site") == "cross-site"
                    or (origin and (urlsplit(origin).netloc != request.url.netloc
                                    or urlsplit(origin).scheme != request.url.scheme))):
                return JSONResponse({"detail": "Cross-origin writes are forbidden"}, status_code=403)
            if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
                return JSONResponse({"detail": "Writes require application/json"}, status_code=415)
            chunks = []
            size = 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > 2 * 1024 * 1024:
                    return JSONResponse({"detail": "Request exceeds 2 MiB"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        request.state.principal = principal
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        return response
