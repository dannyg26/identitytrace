# Architecture

## Status

This documents what's actually built - **every phase in the blueprint's
roadmap, Phase 0 through Phase 8**, plus a post-blueprint **Phase 9**
(see [`phase9-external-evaluation.md`](phase9-external-evaluation.md))
that hardens the evaluation itself: noisy benign personas, a frozen
holdout set, multi-seed statistics, and the real-vendor-telemetry
ingestion path - versus the full blueprint
([`blueprint.pdf`](blueprint.pdf), copied into this directory for
reference), which this project treats as a living reference (§7's
detection examples, §16's reference rules) rather than a checklist that's
now "done and closed."

## Built so far

```
Entra-shaped raw JSON ──┐
GitHub-shaped raw JSON ──┼─> normalizer ─> NormalizedEvent (pydantic) ─┐
M365-shaped raw JSON ────┤                                             │
Already-normalized JSON ─┘                                             │
                                                                       v
                                                    POST /api/events (FastAPI)
                                                                       │
                              build_profile(actor_id, before=event.timestamp)  <- Phase 3, BEFORE insert
                                                                       │
                                              ┌────────────────────────┼──────────────────────┐
                                              v                        v                        v
                                SQLAlchemy -> events table   detection engine (Phase 2,   deviation engine (Phase 3,
                                (SQLite dev / Postgres via    L1 atomic) evaluates YAML     L2 baseline) compares the
                                 DATABASE_URL, compose.yml)   rules -> detection_matches    event to the profile just
                                              │               table (tagged with a         built -> baseline_deviations
                                              │               `signal` name)                table (deviation_type IS
                                              │                        │                     the signal name)
                                              │                        └───────────┬─────────┘
                                              │                                    v
                                              │                  correlation engine (Phase 4, L3): after commit,
                                              │                  re-reads this identity's signals within each
                                              │                  correlation rule's window, looks for its ordered
                                              │                  sequence -> incidents table (score/confidence
                                              │                  explainable via score_breakdown/confidence_breakdown)
                                              │                                    │
              ┌───────────────────────────────┼────────────────────────┬──────────┴──────────┐
              v                                v                        v                      v
  GET /api/events[/{id}]              GET /api/detections,     GET /api/identities   GET /api/incidents[/{id}],
  [/matches|/deviations|/incidents]   /api/matches[/{id}]       [/{actor_id}]         PATCH .../{id}, /api/correlation-rules
  (trace to raw_event_ref)            (rule library)            (baseline + history)  (query, analyst disposition)
              │                                │                        │                      │
              └────────────────────────────────┴────────────┬───────────┴──────────────────────┘
                                                              v
              Dashboard (Jinja2, clean paths - deliberately NOT under /api, see app/main.py docstring):
              "/" overview (incidents+detections+events), "/incidents[/{id}]" queue+detail (evidence
              graph + disposition form), "/events" list, "/rules" library, "/identities[/{actor_id}]"
                                                              ^
                                                              │
                                     build_incident_graph(incident) [Phase 5, NetworkX, on-demand -
                                     not persisted] -> GET /api/incidents/{id}/graph (JSON) and the
                                     dashboard's inline SVG both render from this same graph

app/pipeline.py's normalize_payload() + process_event() [the whole chain above, minus the
HTTP layer] is also called directly by app/evaluation/harness.py (Phase 7): a fixed-seed
labeled benign+attack dataset run against a throwaway in-memory DB -> POST /api/evaluation/run
and the "/evaluation" dashboard page report precision/recall/FPR/latency/alert-reduction,
correlation engine vs. isolated-rule baseline (this project's core research question).
```

Everything through normalization/storage is deterministic. Detection
(Phase 2) is deterministic and strictly single-event - see
[`detections.md`](detections.md). Baselines (Phase 3) look at per-identity
history but still only flag deviations on individual events - see
[`baselines.md`](baselines.md). Correlation (Phase 4) is where those two
layers' output finally combines across events into a scored, explainable
incident - see [`correlation.md`](correlation.md). The identity graph
(Phase 5) visualizes one incident's evidence as typed entities and
relationships, rebuilt on demand rather than persisted - see
[`graph.md`](graph.md). Phases 0-4 are the blueprint's MVP cut line;
Phases 5-7 are "portfolio-grade" polish past it - Phase 6 added a third
telemetry source (M365) with zero changes to detection/baseline/
correlation/incident code, proving the normalize-first architecture pays
off (see [`cross-domain.md`](cross-domain.md)); Phase 7 is where that
whole pipeline finally gets *measured*, not just exercised - see
[`evaluation.md`](evaluation.md).

**Evaluation reuses production code, not a parallel copy.** `app/pipeline.py`
extracts the normalize -> baseline -> persist -> detect -> correlate
sequence that `app/api/events.py` used to inline, specifically so
`app/evaluation/harness.py` could call the *exact same functions* rather
than a second implementation that could quietly drift from what's
actually deployed. This refactor happened as part of building Phase 7,
not before - the API's ingestion endpoint got simpler as a result.

**API/dashboard path separation.** The JSON API is mounted under `/api`;
the dashboard uses clean top-level paths. This was a deliberate fix, not
the original design: Phase 1 registered both a JSON `GET /events` and an
HTML `GET /events` on the same path, and Starlette silently matched
whichever was registered first - the dashboard page was unreachable dead
code until this was caught by manually booting the server (the test suite
didn't catch it, since it only exercised the API). With `/detections`,
`/identities`, and `/incidents` all needing both a JSON and an HTML view,
prefixing the API was the fix that scales instead of relitigating this per
resource.

## Phase 8: portfolio hardening

Every phase in the blueprint's roadmap is now built. Phase 8 added:

- **CI** (`.github/workflows/ci.yml`): lint (`ruff check`), the full test
  suite with a 90% coverage floor (actual: ~97%), and a Docker build +
  boot + smoke test - three jobs, all real, none aspirational.
- **A real packaging bug, found and fixed while writing the Dockerfile**:
  `app/detections/loader.py`, `app/correlation/loader.py`, and
  `app/main.py`'s `DASHBOARD_DIR` all compute their file paths relative to
  the installed `app` package's own location. That only resolves
  correctly when `app/` sits in a source checkout next to `detections/`,
  `correlations/`, and `dashboard/` - true for a local run or an editable
  install (`pip install -e .`, used throughout this project's dev
  workflow and now its Dockerfile too), but a real `pip install .`
  relocates the package into site-packages and silently breaks it -
  verified by literally simulating that relocation before writing the
  fix. Each module now also supports an env var override
  (`IDENTITYTRACE_DETECTIONS_DIR`, `_CORRELATIONS_DIR`, `_DASHBOARD_DIR`)
  for any future packaging change - see
  `tests/unit/test_loader_path_override.py`.
- **`Dockerfile` + `docker-compose.yml`**: `docker compose up --build` runs
  Postgres and the app together end-to-end - not just Postgres alone,
  which is all Phase 1's compose file did.
- **`scripts/seed_demo_data.py`**: populates the app's real (not
  throwaway) database with the same reproducible dataset the evaluation
  harness generates, so a fresh clone has real incidents to click through
  immediately. Tested as an actual subprocess in
  `tests/integration/test_seed_script.py`.
- **`docs/case-studies.md`**: two full investigation walkthroughs using
  real, unedited system output (not hand-written for effect) - one A2,
  one A4, including a case where the incident score's clamp(0, 100)
  actually triggers (raw sum 150 -> 100).
- **Normalizer fidelity check** (`docs/normalizer-fidelity.md`,
  `tests/fixtures/real_samples/`): every normalizer validated against
  fixtures shaped like each source's real, officially-published API
  schema (Microsoft Graph, GitHub's audit log, the O365 Management
  Activity API) rather than only this project's own invented shapes.
  Found and fixed four real bugs - including a dispatch-logic collision
  that would have crashed on a genuine Entra audit payload. This was the
  practical alternative to integrating Splunk BOTS (the blueprint's own
  recommendation, §10.1.1): both BOTS v2 and v3 turned out to be
  distributed exclusively as pre-indexed Splunk databases with no plain-
  file export, requiring an actual running Splunk instance neither built
  nor installed here - a documented, explicit gap, not a silently skipped
  one.

## Phase 9: evaluation hardening (post-blueprint)

Full detail: [`phase9-external-evaluation.md`](phase9-external-evaluation.md),
[`evaluation.md`](evaluation.md), [`holdout.md`](holdout.md),
[`real-lab-collection-guide.md`](real-lab-collection-guide.md). Summary:

- **The dataset stopped being too clean.** `app/evaluation/scenarios.py`
  gained six noisy benign personas and four ambiguous singletons -
  legitimate activity that individually looks alarming. This is what
  turned the isolated-vs-correlation comparison into an actual finding:
  isolated-rule precision drops to 0.596 under this noise while
  correlation holds 1.0 on the identical dataset - previously, with a
  thin benign set, both hit 1.0 and the comparison proved nothing.
- **`app/evaluation/holdout.py` + `holdout_runner.py`**: a separately-
  seeded, separately-composed dataset (a new persona, and an attack
  combination none of the five original correlation rules were written around),
  frozen once to `tests/fixtures/holdout/holdout_v1.json` via
  `scripts/freeze_holdout.py` and never edited to improve a score. First
  run: the novel combination was caught by both detection layers.
- **`run_multi_seed_evaluation()`**: mean ± stdev across several seeds,
  not one deterministic run - with an honestly-reported limitation
  (isolated-rule precision/FPR show zero variance because which specific
  noisy-persona signals fire is currently structurally fixed, not
  randomized; only timing varies).
- **`GET /api/alerts` + `/alerts`**: high/critical atomic matches as their
  own queue, alongside (not replacing) `/incidents` - A6's standalone
  bulk-transfer signal is exactly the case this exists for.
- **`scripts/ingest_real_export.py` + `report_by_provenance.py`**: the
  real-telemetry path. This environment cannot authenticate to Entra or
  GitHub itself (no installed `gh` CLI, no credentials) - these scripts
  are the other half of the division of labor: a user collects a real
  export from their own lab tenant/org
  ([`real-lab-collection-guide.md`](real-lab-collection-guide.md)) and
  hands it over unmodified; results are tagged `real_benign` /
  `real_controlled_attack` and reported separately from the always-
  synthetic harness numbers, never blended. Built and tested against this
  project's own real-schema fixtures; no genuine tenant/org data
  collected yet - an open, explicitly stated gap.

## Key modules

- `app/models/event.py` - `NormalizedEvent` (Pydantic, validation) and
  `EventRecord` (SQLAlchemy, persistence), covering every field in the
  blueprint's §6.2 schema.
- `app/normalizers/entra.py`, `github.py`, `m365.py` - raw payload ->
  `NormalizedEvent`. `m365.py` (Phase 6) is the proof that this seam scales
  to a new source without touching detection/baseline/correlation code.
- `app/api/events.py` - ingestion (`POST /api/events`) and query, plus the
  per-event evidence endpoints (`/matches`, `/deviations`, `/incidents`).
- `app/detections/schema.py`, `loader.py`, `engine.py` - the rule schema
  (each rule tagged with a correlation `signal`), YAML loader/validator,
  and pure evaluator. See [`detections.md`](detections.md).
- `app/api/detections.py` - rule library and match query API.
- `app/models/detection.py` - `DetectionMatchRecord` persistence.
- `app/baselines/profile.py`, `deviation.py` - the per-identity baseline
  builder and pure deviation evaluator. See [`baselines.md`](baselines.md).
- `app/api/identities.py` - identity profile API; `load_identity_context()`
  is shared with the dashboard's identity pages.
- `app/models/baseline.py` - `BaselineDeviationRecord` persistence.
- `app/correlation/signals.py`, `engine.py`, `scoring.py`, `build.py`,
  `run.py`, `schema.py`, `loader.py` - the Phase 4 pipeline: unify
  matches+deviations into signals, find an ordered chain, score/explain it,
  build the incident payload. See [`correlation.md`](correlation.md).
- `app/api/incidents.py` - incident query/disposition API and the
  correlation-rule registry (mirrors `app/api/detections.py`'s pattern).
- `app/models/incident.py` - `IncidentRecord` persistence, and
  `upsert_incident()`'s analyst-triage-preserving update rule.
- `app/graph/build.py`, `serialize.py`, `svg.py` - the per-incident
  NetworkX graph, its JSON form, and its inline-SVG rendering. See
  [`graph.md`](graph.md).
- `app/pipeline.py` - the shared normalize -> baseline -> persist ->
  detect -> correlate sequence, called by both `app/api/events.py` and
  the evaluation harness.
- `app/evaluation/scenarios.py`, `metrics.py`, `harness.py` - the labeled
  dataset generators (including the noisy personas and ambiguous
  singletons), metrics computation (recall/precision/F1/FPR/latency/
  alert-reduction), and the harness (single-run and multi-seed) that ties
  them to `app/pipeline.py` against a throwaway in-memory DB. See
  [`evaluation.md`](evaluation.md).
- `app/evaluation/holdout.py`, `holdout_runner.py` - the frozen
  out-of-sample dataset generator and the loader that runs the checked-in
  file (never regenerates it) through the same pipeline. See
  [`holdout.md`](holdout.md).
- `app/api/evaluation.py` - `POST /api/evaluation/run`.
- `scripts/ingest_real_export.py`, `report_by_provenance.py`,
  `freeze_holdout.py` - the real-telemetry ingestion path, its
  provenance-segmented reporting, and the one-time holdout freeze. See
  [`real-lab-collection-guide.md`](real-lab-collection-guide.md).
- `app/models/db.py` - `DATABASE_URL`-driven engine/session; SQLite by
  default, Postgres-ready.
- `dashboard/templates/` - server-rendered overview, incidents (queue +
  detail, with an evidence graph and a disposition form), events, rules,
  identity, and evaluation pages.
