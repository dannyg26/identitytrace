"""Generate a separate Entra deployment bundle. Does not deploy or change Entra."""

import argparse
import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import yaml


def create_bundle(root, slug, tenant_id, client_id, api_id, public_url, https_port=8443):
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,39}", slug):
        raise ValueError("Customer slug must be 3-40 lowercase letters, digits or hyphens")
    tenant_id, client_id, api_id = str(UUID(tenant_id)), str(UUID(client_id)), str(UUID(api_id))
    if client_id == api_id:
        raise ValueError("Browser client and API must use separate application registrations")
    origin = urlsplit(public_url)
    if (origin.scheme != "https" or not origin.hostname or origin.path not in ("", "/")
            or origin.query or origin.fragment or origin.username or origin.password
            or not re.fullmatch(r"[a-zA-Z0-9.-]+", origin.hostname)):
        raise ValueError("Public URL must be an HTTPS origin with a DNS hostname")
    if not 1024 <= https_port <= 65535:
        raise ValueError("Local HTTPS port must be between 1024 and 65535")
    # Force validation before creating any files (urlsplit defers invalid port errors).
    if origin.port is not None and not 1 <= origin.port <= 65535:
        raise ValueError("Public URL has an invalid port")
    target = Path(root).resolve() / slug
    target.mkdir(parents=True, exist_ok=False)
    secret_dir = target / "secrets"
    secret_dir.mkdir(mode=0o700)
    for filename, value in {"db-password.txt": secrets.token_urlsafe(40),
                            "db-admin-password.txt": secrets.token_urlsafe(40),
                            "session-secret.txt": secrets.token_urlsafe(48),
                            "client-secret.txt": "", "tls-cert.pem": "", "tls-key.pem": ""}.items():
        fd = os.open(secret_dir / filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    environment = {
        "IDENTITYTRACE_ENV": "production", "IDENTITYTRACE_DB_HOST": "postgres",
        "IDENTITYTRACE_DB_PASSWORD_FILE": "/run/secrets/db_password",
        "IDENTITYTRACE_ORGANIZATION_ID": tenant_id,
        "IDENTITYTRACE_OIDC_ISSUER": authority + "/v2.0",
        "IDENTITYTRACE_OIDC_JWKS_URL": authority + "/discovery/v2.0/keys",
        "IDENTITYTRACE_OIDC_AUDIENCE": api_id,
        "IDENTITYTRACE_OIDC_CLIENT_ID": client_id,
        "IDENTITYTRACE_OIDC_CLIENT_SECRET_FILE": "/run/secrets/client_secret",
        "IDENTITYTRACE_SESSION_SECRET_FILE": "/run/secrets/session_secret",
        "IDENTITYTRACE_PUBLIC_URL": public_url.rstrip("/"),
        "IDENTITYTRACE_OIDC_AUTHORIZE_URL": authority + "/oauth2/v2.0/authorize",
        "IDENTITYTRACE_OIDC_TOKEN_URL": authority + "/oauth2/v2.0/token",
        "IDENTITYTRACE_OIDC_SCOPE": f"openid profile api://{api_id}/access_as_user",
        "IDENTITYTRACE_OIDC_ORG_CLAIM": "tid", "IDENTITYTRACE_OIDC_SUBJECT_CLAIM": "oid",
        "IDENTITYTRACE_OIDC_ROLE_MAP": json.dumps({f"IdentityTrace.{role.title()}": role
                                                   for role in ("viewer", "analyst", "admin", "ingestor")}),
    }
    app = {"build": str(Path(__file__).resolve().parents[1]), "environment": environment,
           "secrets": ["db_password", "client_secret", "session_secret"], "read_only": True,
           "tmpfs": ["/tmp:size=64m,mode=1777"], "cap_drop": ["ALL"],
           "security_opt": ["no-new-privileges:true"], "mem_limit": "1g", "pids_limit": 128,
           "command": ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000",
                       "--proxy-headers", "--forwarded-allow-ips=*", "--no-access-log"],
           "depends_on": {"postgres": {"condition": "service_healthy"}}}
    compose = {"name": "identitytrace-" + slug, "services": {
        "postgres": {"image": "postgres:17-alpine", "environment": {
            "POSTGRES_USER": "identitytrace_owner", "POSTGRES_DB": "identitytrace",
            "POSTGRES_PASSWORD_FILE": "/run/secrets/db_admin_password"}, "secrets": ["db_password", "db_admin_password"],
            "volumes": ["data:/var/lib/postgresql/data", "./init-database.sh:/docker-entrypoint-initdb.d/10-identitytrace.sh:ro"],
            "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U identitytrace_owner -d identitytrace"],
                            "interval": "5s", "timeout": "5s", "retries": 10}},
        "app": app,
        "gateway": {"image": "caddy:2", "ports": [f"127.0.0.1:{https_port}:443"],
                    "volumes": ["./Caddyfile:/etc/caddy/Caddyfile:ro"],
                    "secrets": ["tls_certificate", "tls_private_key"], "depends_on": ["app"]}},
        "volumes": {"data": {}}, "secrets": {
            key: {"file": "./secrets/" + file} for key, file in {
                "db_password": "db-password.txt", "session_secret": "session-secret.txt",
                "db_admin_password": "db-admin-password.txt",
                "client_secret": "client-secret.txt", "tls_certificate": "tls-cert.pem",
                "tls_private_key": "tls-key.pem"}.items()}}
    for service in compose["services"].values():
        service["restart"] = "unless-stopped"
        service["logging"] = {"options": {"max-size": "10m", "max-file": "3"}}
    (target / "compose.yml").write_text(yaml.safe_dump(compose, sort_keys=False), encoding="utf-8")
    (target / "init-database.sh").write_text(
        '#!/bin/sh\nset -eu\n'
        'psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=ON_ERROR_STOP=1 '
        '--set=app_password="$(cat /run/secrets/db_password)" <<\'SQL\'\n'
        "CREATE ROLE identitytrace LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD :'app_password';\n"
        "ALTER DATABASE identitytrace OWNER TO identitytrace;\n"
        "REVOKE CONNECT ON DATABASE identitytrace FROM PUBLIC;\n"
        "GRANT CONNECT ON DATABASE identitytrace TO identitytrace;\n"
        "SQL\n", encoding="utf-8", newline="\n")
    (target / "Caddyfile").write_text(
        ":443 {\n  tls /run/secrets/tls_certificate /run/secrets/tls_private_key\n"
        f"  @wronghost not host {origin.hostname}\n  respond @wronghost 421\n"
        "  reverse_proxy app:8000\n}\n", encoding="utf-8")
    (target / "customer.json").write_text(json.dumps({"slug": slug, "tenant_id": tenant_id,
        "client_id": client_id, "api_id": api_id, "public_url": public_url.rstrip("/"),
        "database_isolation": "dedicated Compose project, network and PostgreSQL volume"}, indent=2), encoding="utf-8")
    (target / ".gitignore").write_text("secrets/\n", encoding="utf-8")
    (target / "START.md").write_text(
        "# Customer deployment\n\nThis bundle has not been deployed. Keep secrets out of source control.\n\n"
        "1. Register the browser client and API in Entra using docs/entra-setup.md.\n"
        f"2. Register exactly `{public_url.rstrip('/')}/auth/callback` as a Web redirect URI.\n"
        "3. Put the browser client secret in secrets/client-secret.txt and your trusted TLS certificate/key in secrets/tls-cert.pem and secrets/tls-key.pem.\n"
        "4. Allow container UID 10001 to read the mounted app secrets and the database container's postgres user to read both database password files. File-backed Compose secrets retain host file permissions; verify these before startup. On Windows, restrict the secrets directory ACL to your user.\n"
        "5. Run `docker compose up -d postgres`.\n"
        f"6. Run `docker compose run --rm --build app python scripts/migrate_database.py --organization-id {tenant_id}`.\n"
        "7. Run `docker compose up --build -d`. Verify HTTPS login, logout and wrong-tenant denial.\n\n"
        "Only the gateway port is published, on loopback. The application and database have no host ports. "
        "An external load balancer or an explicitly reviewed port binding is needed for remote access. "
        "The public origin must route to this gateway with its original Host header. "
        "Forwarded headers are trusted only because the app is confined to this dedicated stack's private network. "
        "Do not join unrelated containers to that network. Back up and test recovery before adding real data.\n", encoding="utf-8")
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("slug")
    for name in ("tenant-id", "client-id", "api-id", "public-url"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output-root", type=Path, default=Path("deployments"))
    parser.add_argument("--https-port", type=int, default=8443)
    args = parser.parse_args()
    print(create_bundle(args.output_root, args.slug, args.tenant_id, args.client_id,
                        args.api_id, args.public_url, args.https_port))


if __name__ == "__main__":
    main()
