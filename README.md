# IdentityTrace

IdentityTrace brings cloud identity and audit logs into one investigation workflow.
It connects authentication, OAuth consent, privilege changes, and data access into
incidents that analysts can review, annotate, and export as Word reports.

Built with Python, FastAPI, SQLAlchemy, and PostgreSQL, it uses transparent detection
rules and behavioral baselines to explain why activity was flagged. It is a defensive
research project with a working application and documented validation limits.

## What it does

| Capability | How it helps |
|---|---|
| Normalize telemetry | Converts Microsoft Entra, GitHub, and Microsoft 365 audit payloads into a common event schema |
| Detect suspicious activity | Applies 14 atomic rules to authentication, consent, privilege, developer-token, and data-access events |
| Establish identity baselines | Flags unfamiliar devices, IPs, countries, applications, login hours, and unusual activity volume |
| Connect related events | Uses six temporal correlation rules to assemble findings with evidence and explainable scores |
| Investigate findings | Provides incident and alert queues, identity profiles, evidence graphs, notes, assessments, and status tracking |
| Export reports | Produces Word incident and summary reports with plain tables, evidence fingerprints, and CSV exports |
| Control access | Supports Microsoft Entra browser sign-in with PKCE, organization-scoped authorization, and explicit roles |
| Evaluate detection quality | Compares rules and correlation using synthetic scenarios, a frozen holdout, and separately labeled telemetry |

Findings support analyst decisions. They do not establish compromise or automatically
block accounts, revoke tokens, or remediate incidents. Microsoft Entra provides sign-in
and telemetry; the Python application performs detection and correlation.

## How it works

```text
Entra / GitHub / Microsoft 365 logs
                 |
      Collection scripts or API import
                 |
       Common event schema + storage
                 |
       Rules + identity baselines
                 |
        Temporal correlation
                 |
     Incidents and evidence graphs
                 |
     Analyst review / Word reports
```

Manual Entra and GitHub collection/import scripts are included. They require your own
accounts, permissions, and configuration; installing the application does not start
continuous log collection. Microsoft 365 payloads can be imported through the API.

See the [architecture](docs/architecture.md), [detection library](docs/detections.md),
and [investigation walkthroughs](docs/case-studies.md) for implementation details.

## Validation

| Check | Recorded result | What it establishes |
|---|---|---|
| Automated tests | 543 tests passed; 97% application coverage | Tested behavior against the included fixtures |
| GitHub CI | Lint, full suite, PostgreSQL integration, and Docker build/smoke checks passed | The checked-in application builds and passes these checks on Linux |
| Azure acceptance exercise | Four synthetic events, one expected three-event incident, duplicate replay handled, notes and Word export persisted | A working HTTPS and Entra sign-in workflow with PostgreSQL |
| Local PostgreSQL/TLS lab | 300/300 requests; 300 events; 100 incidents; backup/restore fingerprints matched | Short-run functional, isolation, and recovery checks |
| Controlled real-telemetry study | 238 labeled events from Entra and GitHub | Limited detection evidence, detailed below |

These checks do not establish sustained capacity, enterprise detection accuracy, or
production readiness. See the [validation record](docs/validation.md) and
[GitHub checks](https://github.com/dannyg26/identitytrace/actions).

## Evidence & results

<img src="docs/evidence/architecture-diagram.png" alt="Ingestion through normalizers, common event schema, atomic detections, alerts, correlation, incidents/workflow review, and the analyst dashboard, with a parallel evaluation/provenance path" width="900">

Real Microsoft 365 tenant + real GitHub personal security-log telemetry, captured end-to-end
through the live pipeline (screenshots below have every identifier -
tenant domain, IPs, service-principal/object IDs - replaced with stable
placeholders; nothing else is edited - see
[`docs/evidence-pack.md`](docs/evidence-pack.md)):

| Real A2 workflow | Benign twin (same rule, same score) |
|---|---|
| ![Real A2 admin-consent workflow incident](docs/evidence/01-real-a2-workflow.png) | ![Benign twin triggering the identical workflow](docs/evidence/02-a2-benign-twin.png) |

Same rule (`IDT-CORR-006`), same three-step chain, same score (`75 / high`)
for both a controlled attack sequence and a legitimate admin approval - the
finding the rule is now classified around: it detects the *workflow*, not
intent. See [`docs/evaluation.md`](docs/evaluation.md), "A2 Benign Twin —
Detection vs Intent", for the full analysis, and
[`docs/evidence/raw-to-detection-proof.md`](docs/evidence/raw-to-detection-proof.md)
for one real event traced raw -> normalized -> detected end to end.

More: [atomic alert queue](docs/evidence/03-real-atomic-alerts.png) ·
[final real-data metrics](docs/evidence/04-final-real-metrics.png) ·
[provenance breakdown](docs/evidence/05-provenance-breakdown.png) ·
[tests & lint](docs/evidence/06-tests-and-lint.png)

**Controlled-lab results** (real data, `scripts/real_metrics_report.py`; full
detail and every caveat in [`docs/evaluation.md`](docs/evaluation.md)):

| | Isolated rules | Correlation |
|---|---|---|
| Recall (attack-export denominator) | 1.000 (7/7) | 0.286 (2/7) |
| Precision | 0.575 | 0.500 |
| False-positive rate | 0.081 | 0.143 |

The two correlated attack exports belong to one of three A2 attempts.
The real-data 20.0 alert/incident ratio is not evidence of useful noise
reduction; GitHub observability is incomplete.

Correlation precision of 0.500 reflects the benign twin
above, kept as evidence that a correlation rule can detect a workflow
without being able to infer intent. Machine-readable versions of all of
this: [`evidence_pack/`](evidence_pack/) (raw redacted vendor events,
IdentityTrace's own processing/detection output, and the evaluation
results, kept as three separate tiers).

## Dataset and limitations

The real-telemetry corpus contains 238 events: 213 Entra events across four sparse
calendar dates and 25 GitHub events on one date. Seven attack-labeled export files
represent three A2 attempts and two A4 attempts, not seven independent workflows.
It includes one benign A2 twin and an 11-event revocation experiment. Synthetic
benchmarks, frozen holdout results, and real telemetry are reported separately.

- Collection duration, identity count, and baseline history are limited.
- GitHub telemetry did not expose the full A4 chain, including clone/content access.
- Legitimate consent and a controlled attack can produce the same workflow finding.
- A6 is missed by correlation in the frozen holdout, although atomic rules fire.
- Broader independently labeled data and sustained authenticated cloud load remain unverified.
- Azure recovery and notification delivery still require acceptance testing.
- Each organization requires its own deployment and database; shared-database multi-tenancy is unsupported.

No public external dataset was integrated. Longer collection periods, more identities,
and richer GitHub telemetry would strengthen the evaluation. The
[evaluation study](docs/evaluation.md) retains the measurements and experimental context.

## Run locally

There is no active hosted demo. The Azure test deployment was removed at the owner's
request. The application can run locally or be deployed using your own infrastructure.

Use Python 3.12. From the repository directory:

```bash
python -m venv .venv
```

Activate the environment in PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Or in macOS/Linux shells:

```bash
source .venv/bin/activate
```

Install dependencies and optionally load synthetic incidents:

```bash
pip install -e ".[dev]"
python scripts/seed_demo_data.py
```

Enable loopback-only demo mode in PowerShell:

```powershell
$env:IDENTITYTRACE_DEMO_MODE = '1'
uvicorn app.main:app --reload --no-access-log
```

Or in macOS/Linux shells:

```bash
export IDENTITYTRACE_DEMO_MODE=1
uvicorn app.main:app --reload --no-access-log
```

Open [the application](http://127.0.0.1:8000/) or
[interactive API documentation](http://127.0.0.1:8000/docs).
Use `/incidents` to investigate findings and download Word reports, `/alerts` for
atomic alerts, `/identities` for profiles, and `/evaluation` to run synthetic checks.
Local data is stored in the ignored `identitytrace.db` SQLite file.

### Authenticated deployment

Production mode requires HTTPS, organization-scoped OIDC, and a migrated PostgreSQL
database bound to that organization. Follow [Entra setup](docs/entra-setup.md) and
[operations](docs/operations.md) for secret files, database migration, Docker Compose,
monitoring, and recovery. The [Azure deployment guide](docs/azure-pilot.md) describes
the Azure configuration. Deployment files do not provision infrastructure automatically.

### Ingestion guarantees

- Identical normalized event retries are accepted without duplication. Conflicting
  reuse of an event ID returns HTTP `409` and preserves the original evidence.
- Events, detections, baseline deviations, and incidents commit in one transaction.
- Late arrivals rebuild affected baseline and incident evidence while preserving
  analyst notes; unsupported findings are marked superseded.
- Analyst updates can reject stale edits with HTTP `409`.

### Development checks

```bash
ruff check app tests scripts infra
pytest --cov=app --cov-report=term-missing --cov-fail-under=90
```

## Documentation

| Guide | Contents |
|---|---|
| [Architecture](docs/architecture.md) | Data flow, module map, and deployment boundary |
| [Threat model](docs/threat-model.md) | Target attack scenarios and assumptions |
| [Evaluation](docs/evaluation.md) | Synthetic and real-telemetry measurements |
| [Validation record](docs/validation.md) | Functional evidence and remaining verification |
| [Independent evaluation](docs/independent-evaluation.md) | Offline telemetry and label review protocol |
| [Operations](docs/operations.md) | Installation, access, monitoring, and backups |

Synthetic attack generators operate on fixtures in a disposable database. Real
collection and controlled exercises require an environment you are authorized to use.
