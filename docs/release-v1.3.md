# IdentityTrace v1.3 pilot release

IdentityTrace ingests cloud identity and audit events, applies atomic detection
rules and per-identity baselines, and correlates related evidence into incidents
for analyst review. It does not automatically block users or revoke tokens.

## Deployment and evidence

The Azure pilot demonstrated HTTPS, interactive Microsoft Entra authentication,
private PostgreSQL connectivity, ingestion, correlation, analyst notes and Word
report export on 2026-09-29. Four fabricated GitHub-shaped records yielded one
expected three-event incident; replaying the last event did not add a duplicate.
The fourth event was a benign control. This is a functional acceptance exercise,
not an estimate of real-world detection accuracy.

The owner requested removal of hosting on 2026-09-30. The dedicated resource group
was confirmed absent on 2026-10-01. There is no active hosted demo. Source code,
deployment templates, redacted research evidence and synthetic test results remain.
The locally retained Word export is a historical output; its visual layout was
not verified because the available document renderer was missing.

Recorded evidence:

- [Live workflow](../evidence_pack/azure-live-workflow-20260929.json).
- [Local PostgreSQL, TLS, load and restore lab](../evidence_pack/production-lab-v1.3-final.json).
- [Earlier controlled real-telemetry study](evaluation.md).

The earlier v1.0 real-data study is retained with its unfavorable results and
coverage limits. It must not be conflated with the synthetic cloud smoke test.
Manual Entra/GitHub collection and import scripts exist; a continuously running
collector is not provisioned or configured by this release.

## Release cleanup

- Updated the overview to describe implemented functionality.
- Added an explicit analyst assessment field alongside status and notes.
- Clarified reports when no separate assessment has been entered.
- Made the Azure bootstrap command usable from the installed Python package.
- Excluded private deployment state, environment files, token caches, raw vendor
  exports and local database files from publication and container contexts.
- Included CI jobs for lint, tests and coverage, PostgreSQL integration and a
  built-container smoke test. CI never deploys Azure infrastructure.

## Remaining validation

Sustained authenticated cloud load, Azure point-in-time recovery, notification
delivery and broader independently labeled detection evaluation remain unfinished.
Single-instance hosting and one database per organization are deliberate pilot
limits. Test scores and evidence-strength confidence are not probabilities of
compromise or production certification.

## Reproduce locally

Follow the README quick start, then run:

```text
python -m ruff check app tests scripts infra
python -m pytest --cov=app --cov-report=term-missing --cov-fail-under=90
```

Use `gitleaks git --redact` for history scanning. The committed Gitleaks
configuration exempts only an exact invented hash in a documented schema fixture.
Keep real credentials and raw collection output outside version control.
