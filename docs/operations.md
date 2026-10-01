# Operating IdentityTrace

## Deployment boundary

Version 1.3 supports a dedicated organization per application instance and database.
Do not put two customers' data in one database. Organization authorization validates
the configured claim on every access token; it does not partition stored events.
Collectors must ingest only data from the organization that owns the deployment.

Production mode requires PostgreSQL, an already-migrated schema, an HTTPS OIDC issuer
and JWKS endpoint, an API audience, an organization ID and an explicit role mapping.
Demo mode and local password/token authentication are disabled in production mode.
Use tenant-specific issuers, never a multi-tenant `common` issuer. Grant one application
role per principal: viewer, analyst, ingestor, or admin. Multiple distinct mapped roles
are rejected. Use a distinct audience for the API so browser ID tokens cannot be used
as API credentials. Signature, RS256 algorithm, issuer, audience, expiry, issued-at,
subject and organization are validated. JWKS failures reject authentication.

Interactive SSO uses the built-in authorization-code/PKCE flow when browser settings
are provided. See [Entra setup](entra-setup.md) and `scripts/onboard_customer.py` for
the complete customer bundle with TLS gateway. The base production Compose override
is bearer-only; it requires a separately configured TLS reverse proxy and trusted
proxy headers. The app does not trust identity headers. Generated bundles confine
the app to a dedicated private network and publish only a loopback gateway port.
Configure and test the provider in your own tenant; local signed-token tests cannot
validate an external tenant registration. Production rejects plaintext requests.

Verification follows the [PyJWT documentation](https://pyjwt.readthedocs.io/en/stable/usage.html).

## Install and upgrade

1. Create `secrets/db-password.txt` with a long unique database password and create
   `secrets/credentials.json` with `scripts/manage_credentials.py`. The latter is for
   local mode; use `[]` for OIDC-only production. Files must be readable by container
   UID 10001. Protect the containing directory with host permissions; never commit secrets.
2. Set the two file-path variables in `.env` using `.env.example`. Compose mounts
   these files as secrets instead of placing the password in the container environment.
   These are local file mounts, not a managed secret service or encrypted vault.
3. Back up the database. Start PostgreSQL with `docker compose up -d postgres`.
4. Run exactly one migration job:
   `docker compose run --rm --build app python scripts/migrate_database.py --organization-id YOUR-TENANT-ID`.
   Stop old writers during a schema upgrade. Do not run migration jobs concurrently.
5. For a local authenticated stack, run `docker compose up --build -d`.
   For production, set the OIDC values and run
   `docker compose -f docker-compose.yml -f compose.production.yml up --build -d`.
   The production app verifies schema version 3 and the persistent organization
   binding; it will not migrate or bind on startup. Existing databases require an
   explicit first binding after verifying that their data belongs to that tenant.
6. Check `/ready`, ingest a known safe fixture, confirm its expected finding, and
   test an unauthorized principal and an unrelated organization's token.

The container uses a non-root user, read-only root filesystem, dropped capabilities,
bounded temporary storage and log rotation. Start with one app worker; request metrics,
evaluation/export limits and auth throttling are process-local. For multiple replicas,
add gateway-wide rate limiting and scrape each replica. Database writes are serialized;
benchmark throughput before promising ingestion capacity.

## Monitoring

`/health` is process liveness. `/ready` returns 503 when database connectivity or
authentication configuration is unavailable. Neither endpoint returns database details.
`/metrics` requires an admin credential and exposes Prometheus counters for request count
and accumulated duration, labeled by route template, method and status. Scrape over TLS;
never put bearer tokens in query strings. Request logs contain generated request IDs,
route templates, status and duration, without bodies, credentials or query parameters.
Uvicorn's separate access log is disabled in the container to avoid logging raw paths.

Alert on readiness failures, increased 5xx responses, sustained 401/429 responses,
disk capacity, PostgreSQL failures, and a missed backup schedule. Send logs and
`/api/audit` records to protected external storage if you require tamper-resistant history;
database admins can modify the local audit table. No monitoring service is deployed
automatically by these files.

## Backup and recovery

For local SQLite, run:

```text
python scripts/backup_sqlite.py identitytrace.db backups/identitytrace-2026-09-24.db
```

This uses SQLite's online backup API, validates integrity and prints a SHA-256 digest.
It refuses to overwrite a file. To test recovery, point a separate local application
at the backup and compare event, incident and audit counts before accepting it.
Do not copy an active SQLite file without its WAL state.

For PostgreSQL, use the container's native tools. Avoid shell redirection of binary
archives on Windows; create the archive in the container and copy it out:

```text
docker compose exec postgres pg_dump -U identitytrace -d identitytrace -Fc -f /tmp/identitytrace.dump
docker compose cp postgres:/tmp/identitytrace.dump backups/identitytrace.dump
docker compose exec postgres createdb -U identitytrace identitytrace_restore_check
docker compose exec postgres pg_restore -U identitytrace -d identitytrace_restore_check --no-owner --exit-on-error /tmp/identitytrace.dump
docker compose exec postgres psql -U identitytrace -d identitytrace_restore_check -c "SELECT count(*) FROM events"
```

Choose unique archive and restore-database names for every drill. Encrypt backups at
rest, copy them off the host, restrict access, and choose a retention period and backup
frequency appropriate to your recovery objectives. A successful `pg_dump` alone is
not a tested recovery. No remote backups or schedules are configured by this repository.

Version 1.3's `scripts/production_lab.py` performs a complete dump/restore drill
against two isolated local PostgreSQL databases and a fresh restore database. It
also checks real HTTPS certificate validation, PKCE sign-in, logout, wrong-tenant
authorization, database role isolation and concurrent ingestion. Supply the path to
matching PostgreSQL client binaries, a local lab administrator password file, a new
work directory and an evidence report path:

```text
python scripts/production_lab.py --pg-bin PATH-TO-PG-BIN --admin-password-file PATH-TO-LAB-PASSWORD --work-dir NEW-LAB-DIRECTORY --report evidence_pack/production-lab.json
```

Defaults: database `127.0.0.1:55439`, administrator `lab_admin`, HTTPS ports
19443-19445. The script creates uniquely named databases/roles and preserves them
for inspection. Use only a disposable lab cluster; no external hosts are accepted.
It starts and stops its own application/issuer processes, not the PostgreSQL server.
Its private CA is explicitly trusted by test clients without changing the system
trust store. `evidence_pack/production-lab-v1.3-final.json` records the final code
fingerprints, 300/300 requests, 8 workers, and a 2.363-second p95 client latency.
The host was also running regression tests. This short Windows localhost run does
not establish sustained throughput. Docker/Caddy and public Entra/TLS deployment
remain unverified. The earlier v1.3 run is retained for comparison.
Protect lab directories: they contain test credentials, private keys and backup data.

Before serving a recovered deployment, consider clearing `browser_sessions` to
prevent restoring a session that was logged out after the backup. Sessions expire
within 15 minutes, but backup restoration must not be treated as token revocation.

To rotate local credentials, replace the credential file and restart the app. To rotate
the PostgreSQL password, change the role password through your database administration
channel, update the secret file, and restart dependent services; changing a Compose
secret alone does not change an existing PostgreSQL role. Prefer short-lived IdP access
tokens in production. Rotate issuer keys through the provider. JWKS cache lifetime
is five minutes; immediate revocation requires gateway/provider support.

## Reports and research

The incident queue supports text, identity, severity and status filters. The API also
accepts `since` and `until` ISO timestamps (UTC when no offset is supplied). Bookmark
filtered URLs. Download a Word summary (latest 100 matches, total explicitly stated),
a CSV (at most 5000 matches), or an individual Word incident report. Exports are audited;
they include sensitive identity data and inherit the current principal's read permission.
Word evidence hashes cover normalized JSON with sorted keys, compact separators and
ASCII escaping. They establish an export fingerprint, not a signed chain of custody.

Run `python scripts/benchmark.py --output evidence_pack/benchmark-v1.2.json` to produce
five fixed-seed runs. Results include workflow confusion counts, 95% Wilson intervals,
per-seed results, dataset/rule/code fingerprints and dependency versions. Intervals are
descriptive because generated workflows are not independent real-world observations.
Do not mix legacy finding-level precision and workflow recall into a headline F1.
Use the `workflow_metrics` section for comparisons. This does not replace a blinded,
longitudinal evaluation on real benign workloads and independently labeled attacks.
