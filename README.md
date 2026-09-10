# IdentityTrace

Cross-SaaS identity attack detection platform (blue-team research/portfolio
project). Normalizes authentication, OAuth, developer-platform, privilege,
and data-access telemetry into one schema and correlates it into
evidence-backed incidents.

**Current status: every phase in the blueprint's roadmap is built,
Phase 0 through Phase 8.** Normalized telemetry (three sources: Entra,
GitHub, M365), tested atomic detections, behavioral baselines, temporal
correlation into real scored/explainable incidents, a per-incident
identity graph, a reproducible evaluation harness answering the
project's core research question, CI, Docker, a demo-data seed script,
and two real incident case studies - see
[`docs/architecture.md`](docs/architecture.md) for the full module map,
and the blueprint ([`docs/blueprint.pdf`](docs/blueprint.pdf)) for the
complete design this project builds against.

## What's working right now

- A normalized event schema (`app/models/event.py`) covering identity,
  auth, OAuth, session/device, and data-access fields.
- Normalizers that translate Entra-, GitHub-, and M365-shaped raw audit
  payloads into that schema (`app/normalizers/`) - the third source
  (Phase 6) required zero changes anywhere else in the app, see
  [`docs/cross-domain.md`](docs/cross-domain.md).
- A FastAPI ingestion/query API under `/api` (`POST /api/events`,
  `GET /api/events`, `GET /api/events/{id}`) backed by SQLAlchemy (SQLite by
  default, Postgres via `DATABASE_URL`).
- 13 versioned atomic detection rules (`detections/`), evaluated against
  every ingested event, covering all six attack scenarios (A1-A6). See
  [`docs/detections.md`](docs/detections.md). Results: `GET /api/detections`
  (rule library), `GET /api/matches[/{id}]`, `GET /api/events/{id}/matches`.
- Per-identity behavioral baselines - known devices/IPs/countries/apps/
  auth-protocols/login-hours/volume, and deviation flags (new device, new
  country, unusual hour, volume anomaly, ...) evaluated against each
  identity's history at ingestion time. See
  [`docs/baselines.md`](docs/baselines.md). Results:
  `GET /api/identities[/{actor_id}]`, `GET /api/events/{id}/deviations`.
- **Temporal correlation into incidents** - 5 correlation rules chain
  detection matches and baseline deviations for one identity, in order,
  within a time window, into a scored incident with a fully explainable
  score and confidence breakdown. Analyst disposition (status/notes)
  survives re-correlation. See [`docs/correlation.md`](docs/correlation.md).
  Results: `GET /api/incidents[/{id}]`, `PATCH /api/incidents/{id}`,
  `GET /api/events/{id}/incidents`, `GET /api/correlation-rules`.
- **Identity graph** - each incident's evidence rendered as typed
  entities/relationships (identity, session, device, IP, OAuth app,
  permission, resource, privilege) per the blueprint's §8.1 vocabulary,
  built on demand with NetworkX (no persisted graph to keep in sync). See
  [`docs/graph.md`](docs/graph.md). `GET /api/incidents/{id}/graph`, and
  rendered inline as SVG on the incident detail page.
- **Evaluation harness** - a fixed-seed, labeled benign+attack dataset
  (all six scenarios) run through the exact same pipeline the live app
  uses, against a throwaway in-memory database that can never touch real
  data. Reports precision/recall/false-positive-rate/latency/alert-
  reduction, comparing the correlation engine against an isolated-rule
  baseline - the project's core research question, answered with numbers
  instead of an assertion. See [`docs/evaluation.md`](docs/evaluation.md).
  `POST /api/evaluation/run`, dashboard: `/evaluation`.
- A server-rendered dashboard (`/` overview, `/incidents[/{id}]` queue +
  detail with an evidence graph and a disposition form, `/events` list,
  `/rules` detection library, `/identities[/{id}]` profile pages,
  `/evaluation` metrics) - deliberately on separate paths from the JSON
  API, see `app/main.py`'s docstring for why.
- 212 unit + integration tests, ~97% line coverage: schema validation,
  all three normalizers, the detection engine and all 13 rules (positive +
  negative cases each), the baseline profile builder and deviation
  evaluator, the correlation engine/scoring, the identity graph builder/
  renderer, the evaluation harness's generators/metrics, the demo-seed
  script (run as a real subprocess), and a full ingest -> detect ->
  baseline -> correlate -> incident -> graph path with hand-verified
  score/confidence math.
- **Normalizer fidelity check** - every normalizer validated against
  fixtures shaped like each source's real, officially-published API
  schema (Microsoft Graph, GitHub's audit log, the O365 Management
  Activity API), not just this project's own invented shapes. Found and
  fixed 4 real bugs, including a dispatch-logic collision that would have
  crashed on a genuine Entra audit payload. See
  [`docs/normalizer-fidelity.md`](docs/normalizer-fidelity.md) for what
  was checked, what broke, and why full Splunk BOTS integration (the
  blueprint's own dataset recommendation) wasn't feasible here.
- **CI** (`.github/workflows/ci.yml`) - lint, the full test suite with a
  90% coverage floor, and a Docker build-and-boot smoke test, on every
  push/PR.
- **Docker**: `docker compose up --build` runs Postgres and the app
  together end-to-end (see `Dockerfile`, `docker-compose.yml`). Not
  verified with an actual `docker build` in this project's own dev
  environment (Docker isn't installed there) - CI is what actually
  exercises it, and a real packaging bug in the detection/correlation
  rule-loading path was caught and fixed while writing it (see
  [`docs/architecture.md`](docs/architecture.md)'s Phase 8 section).
- **`scripts/seed_demo_data.py`** - populates the app's real database
  with the same reproducible dataset the evaluation harness generates,
  so a fresh clone has real incidents to explore immediately.
- **[`docs/case-studies.md`](docs/case-studies.md)** - two full
  investigation walkthroughs (A2, A4) using real, unedited system output.

## Quick start

```bash
cd identitytrace
python -m venv .venv
. .venv/Scripts/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"

pytest                          # run the test suite

python scripts/seed_demo_data.py  # optional: populate real incidents to explore

uvicorn app.main:app --reload   # serve at http://127.0.0.1:8000
```

Or with Docker (runs Postgres + the app together):

```bash
docker compose up --build
# then, in another terminal, optionally: docker compose exec app python scripts/seed_demo_data.py
```

Then, with the server running:

```bash
curl http://127.0.0.1:8000/health

curl -X POST http://127.0.0.1:8000/api/events \
  -H "Content-Type: application/json" \
  -d '{"source":"entra","raw":{"id":"signin-1","createdDateTime":"2026-09-09T17:02:11Z","userPrincipalName":"alice@example.test","appId":"app-123","ipAddress":"203.0.113.25","status":{"errorCode":0},"authenticationProtocol":"deviceCode"}}'
# -> normalized event, plus a fired IDT-ENTRA-003 (device-code auth) match

curl http://127.0.0.1:8000/api/events
curl http://127.0.0.1:8000/api/detections           # the 13-rule library
curl http://127.0.0.1:8000/api/matches              # everything that's fired so far
curl http://127.0.0.1:8000/api/identities/alice@example.test  # her baseline
curl http://127.0.0.1:8000/api/incidents             # correlated incidents, if any chain completed
curl http://127.0.0.1:8000/api/incidents/{id}/graph   # that incident's evidence graph as JSON
curl -X POST http://127.0.0.1:8000/api/evaluation/run -d '{}' -H "Content-Type: application/json"
# -> precision/recall/FPR/latency for isolated rules vs. the correlation engine
```

Or open http://127.0.0.1:8000/ for the dashboard (`/incidents` for the
queue and per-incident evidence/scoring/disposition, `/events` for the
event list with per-event detections/deviations, `/rules` for the
detection library, `/identities` for behavioral baselines, `/evaluation`
for the precision/recall/FPR report), or
http://127.0.0.1:8000/docs for interactive API docs.

Data lives in a local `identitytrace.db` SQLite file by default
(gitignored). To use Postgres without the full `docker compose up`
(e.g. you're running the app itself outside Docker): `docker compose up
-d postgres`, then set `DATABASE_URL` per `.env.example` - no code
changes required.

## Project layout

See [`docs/architecture.md`](docs/architecture.md) for a diagram and
module map, [`docs/threat-model.md`](docs/threat-model.md) for the attack
scenario catalog (A1-A6) this project targets, and
[`docs/case-studies.md`](docs/case-studies.md) for two real incidents
walked through end to end.

## Ethics & safe testing

This is a defensive research/lab project. The attack scenario generators
(`app/evaluation/scenarios.py`) run only against synthetic fixtures in a
throwaway in-memory database - never real accounts, real tenants, or
third-party systems. See blueprint §13 for the full policy.
