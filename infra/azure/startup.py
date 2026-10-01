"""App Service entry point with an explicit provisioning-only bootstrap mode.

Normal runtime never migrates or grants database privileges.
"""

import os
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from sqlalchemy import URL


def bootstrap_database(environment):
    """Create the least-privilege role and bind the fresh database once."""
    import psycopg
    from psycopg import sql

    admin_password = environment.pop("AZURE_PG_ADMIN_PASSWORD", "").strip()
    if len(admin_password) < 32:
        raise ValueError("Missing bootstrap administrator password")
    host = environment["AZURE_PG_HOST"]
    with psycopg.connect(host=host, dbname="identitytrace", user="identitytrace_admin",
                         password=admin_password, sslmode="verify-full",
                         sslrootcert="/etc/ssl/certs/ca-certificates.crt") as connection:
        exists = connection.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = 'identitytrace'").fetchone()
        if not exists:
            connection.execute(sql.SQL(
                "CREATE ROLE identitytrace LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD {}"
            ).format(sql.Literal(environment["AZURE_APP_DB_PASSWORD"])))
        connection.execute("REVOKE CONNECT ON DATABASE identitytrace FROM PUBLIC")
        connection.execute("GRANT CONNECT ON DATABASE identitytrace TO identitytrace")
        connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        connection.execute("GRANT USAGE, CREATE ON SCHEMA public TO identitytrace")
    # The migration process receives only the restricted application DSN.
    migrated = dict(environment)
    migrated["IDENTITYTRACE_ENV"] = "production"
    migrated["DATABASE_URL"] = URL.create(
        "postgresql+psycopg", username="identitytrace",
        password=environment["AZURE_APP_DB_PASSWORD"], host=host, database="identitytrace",
        query={"sslmode": "verify-full", "sslrootcert": "/etc/ssl/certs/ca-certificates.crt"},
    ).render_as_string(hide_password=False)
    subprocess.run([sys.executable, "-m", "scripts.migrate_database", "--organization-id",
                    environment["IDENTITYTRACE_ORGANIZATION_ID"]], env=migrated, check=True)


def prepare_environment(environment, secret_directory):
    """Convert platform settings to the app's file-secret interface without logging."""
    environment = dict(environment)
    if environment.get("IDENTITYTRACE_DB_HOST") or environment.get("IDENTITYTRACE_DEMO_MODE"):
        raise ValueError("Conflicting database or demo configuration")
    host = environment["AZURE_PG_HOST"]
    if not host.endswith(".postgres.database.azure.com") or "/" in host or ":" in host:
        raise ValueError("Expected an Azure PostgreSQL hostname")
    password = environment.pop("AZURE_APP_DB_PASSWORD")
    if len(password) < 32:
        raise ValueError("Database password must be at least 32 characters")
    environment["DATABASE_URL"] = URL.create(
        "postgresql+psycopg", username="identitytrace", password=password,
        host=host, database="identitytrace",
        query={"sslmode": "verify-full", "sslrootcert": "/etc/ssl/certs/ca-certificates.crt"},
    ).render_as_string(hide_password=False)
    secret_directory = Path(secret_directory)
    for source, target, filename in (
        ("AZURE_OIDC_CLIENT_SECRET", "IDENTITYTRACE_OIDC_CLIENT_SECRET_FILE", "oidc"),
        ("AZURE_SESSION_SECRET", "IDENTITYTRACE_SESSION_SECRET_FILE", "session"),
    ):
        value = environment.pop(source).strip()
        if len(value) < 32:
            raise ValueError("Missing or short authentication secret")
        path = secret_directory / filename
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
        environment[target] = str(path)
    return environment


def main():
    bootstrap_error = None
    if os.environ.get("IDENTITYTRACE_AZURE_PROVISIONING") == "1":
        if os.environ.get("IDENTITYTRACE_AZURE_BOOTSTRAP") == "1":
            environment = dict(os.environ)
            try:
                bootstrap_database(environment)
            except Exception as error:  # Keep the worker available for a safe diagnostic.
                bootstrap_error = f"{type(error).__name__}: {error}"
                for key in ("AZURE_PG_ADMIN_PASSWORD", "AZURE_APP_DB_PASSWORD",
                            "AZURE_OIDC_CLIENT_SECRET", "AZURE_SESSION_SECRET"):
                    bootstrap_error = bootstrap_error.replace(os.environ.get(key, ""), "[REDACTED]")
        # Keep the platform worker/SSH available for private database bootstrap.
        # No application routes, credentials or readiness claim are exposed.
        class ProvisioningHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/__bootstrap_status":
                    body = ("bootstrap failed: " + bootstrap_error) if bootstrap_error else "bootstrap pending"
                    self.send_response(500 if bootstrap_error else 503)
                else:
                    body = "Provisioning; service is not ready."
                    self.send_response(503)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write((body + "\n").encode())

            def log_message(self, *_args):
                pass

        HTTPServer(("0.0.0.0", 8000), ProvisioningHandler).serve_forever()
        return
    # mkdtemp creates a private 0700 directory on the Linux worker's ephemeral disk.
    directory = tempfile.mkdtemp(prefix="identitytrace-secrets-")
    environment = prepare_environment(os.environ, directory)
    # App Service's managed ingress is the only network path to this worker port.
    os.execve(sys.executable, [sys.executable, "-m", "uvicorn", "app.main:app",
              "--host", "0.0.0.0", "--port", "8000", "--workers", "1",
              "--proxy-headers", "--forwarded-allow-ips=*", "--no-access-log"], environment)


if __name__ == "__main__":
    main()
