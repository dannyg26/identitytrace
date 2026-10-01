"""Exercise two isolated PostgreSQL deployments over verified TLS with a local test issuer.

Creates uniquely named lab databases/roles. Never accepts a non-loopback DB host.
This is an integration lab, not validation of an external Entra registration.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import platform
import secrets
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
import psycopg
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from psycopg import sql
from sqlalchemy import URL

ROOT = Path(__file__).resolve().parents[1]


def certificates(root):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IdentityTrace isolated lab CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    (root / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (root / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root / "server.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root / "server.key").chmod(0o600)


class TestIssuer:
    def __init__(self, root, port):
        self.url = f"https://localhost:{port}"
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.clients, self.codes = {}, {}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass  # Authorization codes and cookies must not enter logs.

            def respond(self, status, payload, location=None):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = urlsplit(self.path)
                if path.path == "/jwks":
                    key = jwt.algorithms.RSAAlgorithm.to_jwk(owner.key.public_key(), as_dict=True)
                    return self.respond(200, {"keys": [{**key, "kid": "lab", "use": "sig", "alg": "RS256"}]})
                if path.path != "/authorize":
                    return self.respond(404, {})
                args = {k: v[0] for k, v in parse_qs(path.query).items()}
                client = owner.clients.get(args.get("client_id"))
                if (not client or args.get("redirect_uri") != client["redirect_uri"]
                        or args.get("code_challenge_method") != "S256"
                        or not all(args.get(k) for k in ("nonce", "state", "code_challenge"))):
                    return self.respond(400, {"error": "invalid_request"})
                code = secrets.token_urlsafe(32)
                owner.codes[code] = {**args, "expires": time.time() + 60}
                return self.respond(302, {}, client["redirect_uri"] + "?" + urlencode({"code": code, "state": args["state"]}))

            def do_POST(self):
                args = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()).items()}
                flow = owner.codes.pop(args.get("code"), None)
                client = owner.clients.get(args.get("client_id"))
                challenge = base64.urlsafe_b64encode(hashlib.sha256(args.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
                if (urlsplit(self.path).path != "/token" or not flow or not client
                        or flow["expires"] < time.time() or args.get("client_secret") != client["secret"]
                        or flow["client_id"] != args.get("client_id") or flow["code_challenge"] != challenge
                        or args.get("redirect_uri") != client["redirect_uri"]):
                    return self.respond(400, {"error": "invalid_grant"})
                return self.respond(200, {"token_type": "Bearer", "expires_in": 900,
                    "access_token": owner.token(client["org"], sub="api-subject"),
                    "id_token": owner.token(client["org"], aud=args["client_id"], nonce=flow["nonce"], sub="browser-subject")})

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "server.pem", root / "server.key")
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def token(self, org, **overrides):
        return jwt.encode({"iss": self.url, "aud": "lab-api", "sub": "lab-principal", "oid": "stable-object-id",
            "tid": org, "roles": ["IdentityTrace.Admin"], "iat": int(time.time()), "exp": int(time.time()) + 900,
            **overrides}, self.key, algorithm="RS256", headers={"kid": "lab"})


def create_database(admin, name, role, password=None):
    if password:
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT").format(sql.Identifier(role), sql.Literal(password)))
    admin.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(name), sql.Identifier(role)))
    admin.execute(sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(sql.Identifier(name)))


def database_snapshot(connection):
    tables = connection.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename").fetchall()
    result = {}
    for (table,) in tables:
        rows = connection.execute(sql.SQL("SELECT row_to_json(t) FROM {} t").format(sql.Identifier(table))).fetchall()
        encoded = sorted(json.dumps(row[0], sort_keys=True, separators=(",", ":")) for row in rows)
        result[table] = {"rows": len(rows), "sha256": hashlib.sha256("\n".join(encoded).encode()).hexdigest()}
    return result


def run(args):
    if args.host not in {"127.0.0.1", "localhost"}:
        raise ValueError("This lab only runs against loopback PostgreSQL")
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    certificates(root)
    ca = str(root / "ca.pem")
    issuer = TestIssuer(root, args.issuer_port)
    prefix = "idt_lab_" + secrets.token_hex(4)
    admin_password = args.admin_password_file.read_text().strip()
    admin = psycopg.connect(host=args.host, port=args.port, user=args.admin_user,
                           password=admin_password, dbname="postgres", autocommit=True)
    processes, logs, deployments = [], [], []
    checks = {}
    try:
        for index, organization in enumerate(("lab-org-a", "lab-org-b")):
            name, password = prefix + f"_{index}", secrets.token_urlsafe(32)
            create_database(admin, name, name, password)
            db_url = URL.create("postgresql+psycopg", username=name, password=password,
                                host=args.host, port=args.port, database=name).render_as_string(hide_password=False)
            app_port = args.app_port + index
            base_url = f"https://localhost:{app_port}"
            client_id, client_secret = f"browser-{index}", secrets.token_urlsafe(32)
            secret_path, session_path = root / f"client-{index}.txt", root / f"session-{index}.txt"
            secret_path.write_text(client_secret)
            session_path.write_text(secrets.token_urlsafe(48))
            secret_path.chmod(0o600)
            session_path.chmod(0o600)
            issuer.clients[client_id] = {"org": organization, "secret": client_secret, "redirect_uri": base_url + "/auth/callback"}
            env = {k: v for k, v in os.environ.items() if not k.startswith("IDENTITYTRACE_") and k != "DATABASE_URL"}
            env.update({"DATABASE_URL": db_url, "IDENTITYTRACE_ENV": "production",
                "IDENTITYTRACE_OIDC_ISSUER": issuer.url, "IDENTITYTRACE_OIDC_JWKS_URL": issuer.url + "/jwks",
                "IDENTITYTRACE_OIDC_AUDIENCE": "lab-api", "IDENTITYTRACE_ORGANIZATION_ID": organization,
                "IDENTITYTRACE_OIDC_ROLE_MAP": '{"IdentityTrace.Admin":"admin"}',
                "IDENTITYTRACE_OIDC_CLIENT_ID": client_id, "IDENTITYTRACE_OIDC_CLIENT_SECRET_FILE": str(secret_path),
                "IDENTITYTRACE_SESSION_SECRET_FILE": str(session_path), "IDENTITYTRACE_PUBLIC_URL": base_url,
                "IDENTITYTRACE_OIDC_AUTHORIZE_URL": issuer.url + "/authorize", "IDENTITYTRACE_OIDC_TOKEN_URL": issuer.url + "/token",
                "IDENTITYTRACE_OIDC_SCOPE": "openid lab-api/read", "IDENTITYTRACE_OIDC_SUBJECT_CLAIM": "oid",
                "SSL_CERT_FILE": ca, "REQUESTS_CA_BUNDLE": ca})
            subprocess.run([sys.executable, str(ROOT / "scripts/migrate_database.py"), "--organization-id", organization],
                           cwd=ROOT, env=env, check=True, capture_output=True)
            log = (root / f"app-{index}.log").open("w")
            logs.append(log)
            processes.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                "--port", str(app_port), "--ssl-certfile", str(root / "server.pem"), "--ssl-keyfile", str(root / "server.key"),
                "--no-access-log"], cwd=ROOT, env=env, stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
            for _ in range(100):
                try:
                    if requests.get(base_url + "/ready", verify=ca, timeout=1).status_code == 200:
                        break
                except requests.RequestException:
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("Application did not become ready; inspect lab logs")
            deployments.append({"name": name, "password": password, "org": organization, "url": base_url, "env": env})
        a, b = deployments
        checks["both_production_apps_ready"] = True
        try:
            requests.get(a["url"] + "/ready", timeout=2)
            checks["untrusted_tls_rejected"] = False
        except requests.exceptions.SSLError:
            checks["untrusted_tls_rejected"] = True
        browser = requests.Session()
        browser.verify = ca
        response = browser.get(a["url"] + "/auth/login", timeout=10)
        checks["pkce_login_over_verified_tls"] = response.status_code == 200 and response.url.endswith("/incidents")
        checks["secure_session_cookie"] = any(c.name == "__Host-idt-session" and c.secure for c in browser.cookies)
        checks["logout_revokes_session"] = browser.post(a["url"] + "/auth/logout", json={}, timeout=5).status_code == 200 and browser.get(a["url"] + "/api/events", timeout=5).status_code == 401
        headers_a = {"Authorization": "Bearer " + issuer.token(a["org"])}
        headers_b = {"Authorization": "Bearer " + issuer.token(b["org"])}
        checks["wrong_organization_token_rejected"] = requests.get(a["url"] + "/api/events", headers=headers_b, verify=ca, timeout=5).status_code == 401
        try:
            with psycopg.connect(host=args.host, port=args.port, dbname=a["name"], user=b["name"], password=b["password"]):
                checks["cross_database_connection_rejected"] = False
        except psycopg.OperationalError:
            checks["cross_database_connection_rejected"] = True
        bad_env = {**a["env"], "IDENTITYTRACE_ORGANIZATION_ID": b["org"]}
        # Exercise the binding guard called by the production lifespan.
        probe = subprocess.run([sys.executable, "-c", "from app.models.db import verify_schema; import os; verify_schema(os.environ['IDENTITYTRACE_ORGANIZATION_ID'])"], env=bad_env, cwd=ROOT, capture_output=True)
        checks["wrong_database_binding_rejected"] = probe.returncode != 0 and b"different organization" in probe.stderr

        def ingest(index):
            durations, statuses = [], []
            actor = f"lab-{index}@example.test"
            events = [
                {"event_type": "signin", "action": "login", "auth_protocol": "deviceCode"},
                {"event_type": "oauth_consent", "action": "consent", "permissions": ["Files.Read.All"]},
                {"event_type": "file_access", "action": "read", "resource_type": "mailbox"},
            ]
            with requests.Session() as session:
                for step, event in enumerate(events):
                    payload = {"source": "entra", "actor_id": actor, "actor_type": "user", "result": "success",
                               "event_id": f"lab-{index}-{step}", "timestamp": f"2026-09-01T09:{step * 5:02}:00Z", **event}
                    started = time.perf_counter()
                    reply = session.post(a["url"] + "/api/events", json=payload, headers=headers_a, verify=ca, timeout=60)
                    durations.append(time.perf_counter() - started)
                    statuses.append(reply.status_code)
            return durations, statuses

        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            outcomes = list(pool.map(ingest, range(args.workflows)))
        elapsed = time.perf_counter() - started
        durations = sorted(t for times, _ in outcomes for t in times)
        statuses = [s for _, codes in outcomes for s in codes]
        with psycopg.connect(host=args.host, port=args.port, dbname=a["name"], user=a["name"], password=a["password"]) as conn:
            event_count = conn.execute("SELECT count(*) FROM events").fetchone()[0]
            incident_count = conn.execute("SELECT count(*) FROM incidents WHERE superseded_at IS NULL").fetchone()[0]
            before = database_snapshot(conn)
        checks["concurrent_ingestion_correct"] = all(s == 201 for s in statuses) and event_count == args.workflows * 3 and incident_count == args.workflows
        checks["second_organization_has_no_events"] = requests.get(b["url"] + "/api/events", headers=headers_b, verify=ca, timeout=5).json() == []
        dump = root / "backup.dump"
        pg_env = {**os.environ, "PGPASSWORD": a["password"]}
        suffix = ".exe" if os.name == "nt" else ""
        subprocess.run([str(args.pg_bin / ("pg_dump" + suffix)), "-h", args.host, "-p", str(args.port),
            "-U", a["name"], "-d", a["name"], "-Fc", "-f", str(dump)], env=pg_env, check=True, capture_output=True)
        restore_name = prefix + "_restore"
        create_database(admin, restore_name, a["name"])
        subprocess.run([str(args.pg_bin / ("pg_restore" + suffix)), "-h", args.host, "-p", str(args.port),
            "-U", a["name"], "-d", restore_name, "--no-owner", "--exit-on-error", str(dump)], env=pg_env, check=True, capture_output=True)
        with psycopg.connect(host=args.host, port=args.port, dbname=restore_name, user=a["name"], password=a["password"]) as conn:
            after = database_snapshot(conn)
        checks["all_tables_restored_exactly"] = before == after
        report = {"completed_at": datetime.now(timezone.utc).isoformat(), "environment": {
            "os": platform.system(), "python": platform.python_version(),
            "postgresql": admin.execute("SHOW server_version").fetchone()[0],
            "identity_provider": "local HTTPS test issuer; NOT Microsoft Entra",
            "application_tls": "private lab CA explicitly trusted by clients; no trust-store changes"},
            "implementation_sha256": {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for folder, pattern in (("app", "*.py"), ("scripts", "*.py"), ("detections", "*.yaml"), ("correlations", "*.yaml"))
                for path in sorted((ROOT / folder).rglob(pattern))},
            "checks": checks, "load": {"workers": args.workers, "workflows": args.workflows,
            "requests": len(statuses), "successful_requests": statuses.count(201), "elapsed_seconds": round(elapsed, 3),
            "requests_per_second": round(len(statuses) / elapsed, 2),
            "latency_p50_ms": round(durations[math.ceil(len(durations) * .5) - 1] * 1000, 2),
            "latency_p95_ms": round(durations[math.ceil(len(durations) * .95) - 1] * 1000, 2),
            "latency_max_ms": round(max(durations) * 1000, 2), "events": event_count, "incidents": incident_count},
            "recovery": {"tables": before, "dump_sha256": hashlib.sha256(dump.read_bytes()).hexdigest()},
            "limitations": ["Short local workload, not a sustained capacity claim", "No external Entra tenant or public TLS endpoint tested", "Dedicated databases, not shared-table multi-tenancy"]}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"checks": checks, "load": report["load"], "report": str(args.report)}, indent=2))
        if not all(checks.values()):
            raise RuntimeError("One or more production lab checks failed")
    finally:
        for process in processes:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()
        admin.close()
        issuer.server.shutdown()
        issuer.server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-bin", type=Path, required=True)
    parser.add_argument("--admin-password-file", type=Path, required=True)
    parser.add_argument("--admin-user", default="lab_admin")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=55439)
    parser.add_argument("--issuer-port", type=int, default=19443)
    parser.add_argument("--app-port", type=int, default=19444)
    parser.add_argument("--workflows", type=int, choices=range(1, 1001), default=100)
    parser.add_argument("--workers", type=int, choices=range(1, 33), default=8)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
