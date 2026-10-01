"""Validate organization-scoped OAuth access tokens using an operator-pinned issuer.

No token-supplied URL is fetched. Only RS256 is accepted. This is resource-server
authentication; browser authorization-code login uses this verifier in browser_auth.py.
"""

import json
import os
from urllib.parse import urlsplit

import jwt
from jwt import PyJWKClient


class OIDCVerifier:
    def __init__(self):
        self.issuer = os.environ["IDENTITYTRACE_OIDC_ISSUER"]
        self.audience = os.environ["IDENTITYTRACE_OIDC_AUDIENCE"]
        self.jwks_url = os.environ["IDENTITYTRACE_OIDC_JWKS_URL"]
        self.organization = os.environ["IDENTITYTRACE_ORGANIZATION_ID"]
        self.org_claim = os.environ.get("IDENTITYTRACE_OIDC_ORG_CLAIM", "tid")
        self.roles_claim = os.environ.get("IDENTITYTRACE_OIDC_ROLES_CLAIM", "roles")
        self.role_map = json.loads(os.environ.get("IDENTITYTRACE_OIDC_ROLE_MAP", "{}"))
        if not all((self.audience, self.organization, self.org_claim, self.roles_claim)):
            raise ValueError("OIDC audience, organization and claim names must be nonempty")
        for url in (self.issuer, self.jwks_url):
            parsed = urlsplit(url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise ValueError("OIDC issuer and JWKS URL must be trusted HTTPS URLs")
        if (not isinstance(self.role_map, dict) or not self.role_map
                or any(not isinstance(k, str) or not k or v not in
                       {"viewer", "analyst", "ingestor", "admin"} for k, v in self.role_map.items())):
            raise ValueError("OIDC requires an explicit external-role to application-role mapping")
        self.keys = PyJWKClient(self.jwks_url, timeout=5, lifespan=300)

    def decode(self, token, audience=None):
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise jwt.InvalidTokenError("Unsupported signing algorithm or missing key ID")
        key = self.keys.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], issuer=self.issuer, audience=audience or self.audience,
            options={"require": ["iss", "aud", "exp", "iat", "sub", self.org_claim]},
        )
        if claims[self.org_claim] != self.organization or not claims["sub"]:
            raise jwt.InvalidTokenError("Organization or subject mismatch")
        return claims

    def principal(self, claims):
        from app.security import Principal
        try:
            roles = claims.get(self.roles_claim, [])
            if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
                return None
            mapped = {self.role_map[role] for role in roles if role in self.role_map}
            # Roles are deliberately exclusive: ingestor does not inherit read access.
            if len(mapped) != 1:
                return None
            return Principal(f"oidc:{claims['sub']}", mapped.pop())
        except (KeyError, TypeError):
            return None

    def verify(self, token):
        try:
            return self.principal(self.decode(token))
        except (jwt.PyJWTError, ValueError, TypeError):
            return None
