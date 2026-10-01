# Architecture

IdentityTrace is a Python application that normalizes cloud audit events, detects
suspicious signals, and correlates evidence into incidents for analyst review.
FastAPI serves the JSON API and Jinja dashboard; SQLAlchemy stores the event and
investigation state. SQLite supports local demos, and PostgreSQL is required in
production mode.

## Data flow

```text
Vendor payloads or normalized events
                |
       API / collection import
                |
          Source normalizers
                |
     Event validation and replay checks
                |
     Point-in-time identity baseline
                |
     Atomic rules + baseline deviations
                |
        Temporal correlation
                |
   Commit events, signals, and incidents
                |
   API / dashboard / graphs / Word reports
```

`app/pipeline.py` is shared by live ingestion, imports, and evaluation. Events,
detection matches, deviations, and incidents commit together; a processing error
rolls back the transaction. Identical normalized retries are idempotent. Reusing
an event ID with changed content returns a conflict.

Late events rebuild affected identity baselines and incident evidence within the
rules' time windows. Analyst notes and dispositions survive re-correlation;
findings that lose their supporting evidence are marked superseded.

## Detection and investigation

- **Normalization:** Entra, GitHub, and Microsoft 365 payloads become one validated
  schema. Manual collectors and import scripts feed the same pipeline; continuous
  collection requires operator configuration.
- **Atomic detection:** 14 YAML rules inspect one event at a time. Rules produce
  human-readable match reasons and signals for correlation.
- **Behavioral baselines:** Identity history provides point-in-time context for
  unfamiliar devices, countries, IPs, applications, login hours, and data volume.
- **Temporal correlation:** Six rules link ordered signals within time windows.
  Five operate on a single identity; one bridges an admin consent step through an
  exact shared service principal. That consent finding is a workflow review,
  because legitimate approval can produce the same evidence.
- **Investigation:** The dashboard and API expose incident filters, notes, analyst
  assessments, and status. A shared query layer keeps queue and export filters aligned.
- **Evidence:** NetworkX builds each incident graph on demand for JSON and SVG views.
  Word and CSV reports carry evidence fingerprints. A fingerprint is not a signed
  chain of custody; incident scores are not probabilities of compromise.

See [detections](detections.md), [baselines](baselines.md),
[correlation](correlation.md), and [graphs](graph.md) for detailed behavior.

## Access and deployment

The JSON API lives under `/api`; dashboard routes include `/incidents`, `/alerts`,
`/events`, `/identities`, and `/evaluation`. Browser authentication uses authorization
code plus PKCE and expiring server-side sessions. Access tokens are checked against
an explicit issuer, API audience, organization, and role mapping.

Each organization has a dedicated application deployment and PostgreSQL database.
The database is bound to its owning organization, and production startup checks that
binding and the migrated schema. Organization claims do not partition a shared database.
Production requests require HTTPS; loopback demo mode is a separate local setting.

Containers run as a non-root user. Compose adds filesystem and capability restrictions,
secret-file mounts, and private networking. Request metrics, throttling, and evaluation
limits are process-local, so multiple replicas require gateway-level controls.

See [operations](operations.md) and [Entra setup](entra-setup.md) for configuration.

## Evaluation and verification

Synthetic scenarios, a frozen holdout, and external telemetry evaluation all reuse
the application pipeline in disposable databases. Workflow labels are assessed after
detection rather than supplied as detector inputs. Synthetic and real-telemetry metrics
are reported separately, including false positives, missed attacks, and unknown cases.

GitHub CI runs lint, coverage-gated tests, PostgreSQL integration, and a Docker build
and authenticated ingestion smoke test. Packaged YAML rules and dashboard templates
are resolved from the source tree or installed package data, with explicit path
overrides available. See [evaluation](evaluation.md) and [validation](validation.md)
for measured results and limits.

## Module map

| Area | Files | Responsibility |
|---|---|---|
| Application | `app/main.py`, `app/api/` | Routes, startup, API, and dashboard views |
| Pipeline | `app/pipeline.py`, `app/writes.py` | Ingestion, transactions, and reconciliation |
| Event schema | `app/models/event.py`, `app/normalizers/` | Validation, normalization, and persistence |
| Detection | `app/detections/`, `detections/` | Atomic rule definitions, validation, and evaluation |
| Baselines | `app/baselines/` | Identity profiles and deviation checks |
| Correlation | `app/correlation/`, `correlations/` | Signal chains, scoring, and incident construction |
| Identity links | `app/identity.py`, `app/models/operations.py` | Explicit source-to-identity relationships |
| Access | `app/security.py`, `app/oidc.py`, `app/browser_auth.py` | Roles, token verification, and browser sessions |
| Investigation | `app/incident_query.py`, `app/reports.py`, `app/graph/` | Filters, document exports, and evidence graphs |
| Operations | `app/observability.py`, `app/api/operations.py` | Readiness, metrics, and audit access |
| Evaluation | `app/evaluation/` | Generators, holdout, external labels, and metrics |
| Storage | `app/models/`, `scripts/migrate_database.py` | Database models, schema migration, and organization binding |
| Interface | `dashboard/templates/` | Server-rendered tables and investigation pages |
| Deployment | `Dockerfile`, Compose files, `infra/azure/` | Container and Azure configuration |
| Utilities | `scripts/` | Collection, onboarding, imports, backups, and lab checks |
