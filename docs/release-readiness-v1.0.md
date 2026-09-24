# Final Release Status

Final v1.0 review completed on 2026-09-23 (America/New_York).
Ready for the owner's review and manual commit/tag, with the accepted
limitations below. No staging, commit, tag or push was performed.

IdentityTrace normalizes identity/SaaS events, applies 14 atomic rules and
six correlation rules, and presents explainable incidents and workflow
reviews to an analyst. v1.0 validates the pipeline on synthetic scenarios,
a frozen synthetic holdout, and a small real Entra/GitHub lab corpus.
These are separate evidence sets, not a combined precision claim.

The strongest real findings remain: cumulative consent scopes inflated
alerts until scoring used newly added scopes; a legitimate admin-consent
twin matched the controlled A2 workflow identically; and Add/Remove grant
names alone did not establish the direction of a permission change.
The final rule is classified as workflow review, with intent unresolved.

No new collection, external dataset, detector/correlation/scoring change,
or research expansion was made in this release pass. Package and API
version metadata now both read `1.0.0`.

# Files Changed

This final pass changed:

- `README.md`: closed v1.0 scope, dataset/denominator clarification,
  accepted limitations, optional v1.1 roadmap, accurate GitHub source.
- `docs/evaluation.md`: corrected stale no-real-data/open-work claims,
  distinguished historical experiments from the final endpoint, and
  explained per-export versus unique-incident reporting.
- `docs/correlation.md`, `docs/detections.md`: removed stale phase promises;
  clarified that A6 signal overlap does not establish correlation coverage.
- `docs/holdout.md`, `docs/architecture.md`: clarified the five original
  correlation rules in historical holdout descriptions.
- `docs/evidence-pack.md`, `evidence_pack/README.md`,
  `docs/evidence/raw-to-detection-proof.md`: corrected screenshot inventory,
  redaction scope, placeholder consistency and reproduction claims.
- `docs/release-snapshot-2026-09-22.md`: marked as a historical snapshot.
- `docs/phase9-external-evaluation.md`,
  `docs/phase9b-first-collection-checklist.md`,
  `docs/real-lab-collection-guide.md`: marked old collection plans as
  historical references, not outstanding v1.0 requirements.
- `tests/integration/test_correlation_bridged_dashboard.py`,
  `tests/integration/test_correlation_bridged_pipeline.py`,
  `tests/integration/test_grant_remove_semantics.py`,
  `tests/unit/test_correlation_bridged.py`, `tests/unit/test_normalizers.py`:
  replaced copied tenant-specific IDs, real IPs and a GitHub username with
  consistent test placeholders; test logic is unchanged.
- `.dockerignore`: excludes raw data, token cache and coverage artifacts
  from the build context.
- `pyproject.toml`, `app/main.py`: release version metadata only.
- This review and [`release-files-v1.0.txt`](release-files-v1.0.txt): final
  release record and explicit full-tree file manifest.

The existing Phase 9/9B implementation changes predate this pass. They are
part of the intended v1.0 release and are listed in the Git status below.
No unrelated change was identified among the reviewed candidate paths;
this is not a new line-by-line audit of the entire implementation.

# Files To Exclude

- Everything in `real_data/` except its public `README.md`.
- `.entra_token_cache.json`, `.env`, local databases and SQLite journals.
- `.venv/`, Python/pytest/ruff caches, egg-info and coverage output.
- Private exports, credentials, temporary passwords and local audit scratch
  files. Scratch validation ran outside the repository.

None of these private/generated paths is in the release manifest. The
private corpus and live database were not regenerated or modified.
No accidental debug/temp files were found among release candidates.

# Final Tests / Coverage / Lint

- Full suite in an isolated source copy, with no live database, token cache
  or private exports: **412 passed, 2 warnings**, 66.66 seconds.
- Coverage: **97.61%** (98% rounded), 1,926 statements / 46 missed;
  the 90% floor passes.
- After the final username-placeholder edit: **23 normalizer tests passed**.
- Ruff: **All checks passed**. Staged and unstaged whitespace checks pass.
- Warnings: existing Starlette/httpx and anyio deprecations.
- The clean copy used the existing Python 3.12 virtual environment;
  dependency installation and Docker/CI were not freshly validated.

Reproduction commands from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --cov=app --cov-report=term-missing --cov-fail-under=90
.\.venv\Scripts\python.exe -m ruff check .
```

# Final Synthetic Results

Fresh output is structurally identical to
`evidence_pack/03_evaluation_results/synthetic_and_holdout_final.json`.

| Seed 42 | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|
| Isolated rules | 0.596 | 1.000 | 0.747 | 0.239 |
| Correlation | 1.000 | 0.833 | 0.909 | 0.000 |

Five seeds (10/20/30/40/50), eight instances per attack type: correlation
recall mean 0.829, stdev 0.009; precision mean 1.000 and FPR mean 0.000.
Every per-seed result and aggregate matched the saved evidence.

# Final Holdout Results

Frozen holdout output matched in full; its fixture was not edited.

| Frozen holdout | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|
| Isolated rules | 0.712 | 1.000 | 0.832 | 0.198 |
| Correlation | 1.000 | 0.857 | 0.923 | 0.000 |

21 attack scenarios; 73 atomic alerts; 18 incidents; alert/incident ratio
4.06. A6 correlation recall remains 0.0. The holdout is a fixed regression
benchmark from the same project, not independent enterprise validation.

# Final Real-Data Results

238 labeled events: 213 Entra over four sparse calendar dates
(September 11, 14, 15 and 21), and 25 GitHub on September 15. The Entra
actor strings include aliases and an unknown actor; they should not be
counted as independent people. The collection history describes three
test users, an admin and the personal account. GitHub has one actor.

Seven attack exports represent three A2 attempts and two A4 attempts.
The 209 benign events include one A2 twin (nine events) and a revocation
experiment (11 events). GitHub evidence is from personal security-log
exports; org audit API collection was unavailable in the tested setup.

| Real corpus | Precision | Recall by attack export | F1 | FPR |
|---|---:|---:|---:|---:|
| Isolated rules | 0.575 | 1.000 (7/7) | 0.730 | 0.081 |
| Correlation | 0.500 | 0.286 (2/7) | 0.364 | 0.143 |

The two correlated attack exports belong to one A2 attempt. One controlled
A2 workflow and one benign twin yield two workflow-review incidents, both
score 75/high. Raw telemetry confirms both workflows (2/2); it does not
establish malicious intent. Neither has independent escalation evidence.
The 20.0 alert/incident ratio is degenerate and is not useful noise-reduction
proof given incomplete observation and the benign twin.

Validation used a SQLite backup of the existing private lab database, with
all provenance event IDs present. Real metrics and provenance output match
the saved evidence; workflow output matches after identifier redaction.
The eight stored grant-processing rows and zero consent alerts match the
current database, as do the stored incidents' scores and semantics. The
historical before/after revocation claim remains the recorded experiment;
this release pass did not repeat that live experiment.

The provenance report counts the benign incident once in each participating
export (two memberships); the metric report counts one unique false
positive. Its legacy `runs` wording means exports. Public users can rerun
synthetic/holdout evaluation; full real evaluation requires the private
corpus/database and cannot be rebuilt from redacted evidence alone.

# Final Limitations

Limited real duration, users and fully observed workflow instances; sparse
baseline history; incomplete GitHub visibility; workflow detection does
not prove malicious intent; no enterprise generalization. The A6 holdout
correlation gap remains documented. No public external dataset was
integrated: the considered candidates were not a sufficiently clean,
practical fit for core identity/SaaS detection and correlation.

Possible v1.1 work: longitudinal 7-14 day Entra collection, more identities,
repeated A2/twin workflows, richer baseline validation and more GitHub
activity if suitable telemetry becomes available. None is a v1.0 criterion.
A demo GIF/video is not included; six screenshots and a diagram are present.

# Privacy / Secret Check

The final working candidates and existing index were scanned for known
private corpus identifiers and common credential/key/token patterns.
Copied real IDs/IPs/usernames found in five test files were replaced with
placeholders. No remaining known private identifier or credential pattern
was found; this is a bounded scan, not a guarantee against every possible
secret format. No password/token literal or private raw telemetry is staged.

`git check-ignore` confirms the raw exports, token cache, database and
coverage artifacts are excluded. Only `real_data/README.md` is includable.
The existing index has no private paths; its content hash is unchanged.
All six screenshots and the architecture diagram were visually inspected:
visible tenant/user/IP/object identifiers use public placeholders.
Machine-readable JSON files parse; the saved results remain unchanged.
README local links/images resolve. Public Microsoft application IDs are
retained, while tenant-specific object IDs are anonymized.

Redacted evidence is not byte-identical raw data. Some user-agent version
strings were also redacted by the earlier scrub, and placeholder aliases
vary between artifacts. These limits are now explicit in the evidence guide.

# Git Status Review

Branch `master`; current HEAD `4308c1d`; no existing tags.
The index was left exactly as found. **Restaging the reviewed working files
is necessary**: some staged versions predate subsequent fixes.

- 28 paths have staged changes.
- 37 tracked paths have unstaged changes (overlap is expected).
- 39 untracked files are intended release candidates.
- 184 total paths in the full release manifest.

The exact full release tree is listed in
[`release-files-v1.0.txt`](release-files-v1.0.txt), one repository-relative
path per line. It includes this review, itself, existing tracked source,
new Phase 9/9B files, public evidence, and `real_data/README.md` only.
It excludes ignored/private material. Review that manifest before staging.

```text
 M .dockerignore
 M .gitignore
MM README.md
M  app/api/detections.py
 M app/api/incidents.py
 M app/baselines/deviation.py
 M app/correlation/build.py
 M app/correlation/engine.py
 M app/correlation/run.py
 M app/correlation/schema.py
 M app/correlation/scoring.py
 M app/correlation/signals.py
M  app/evaluation/harness.py
A  app/evaluation/holdout.py
A  app/evaluation/holdout_runner.py
M  app/evaluation/metrics.py
MM app/evaluation/scenarios.py
MM app/main.py
 M app/models/db.py
 M app/models/event.py
 M app/models/incident.py
 M app/normalizers/entra.py
 M app/normalizers/github.py
A  dashboard/templates/alerts.html
M  dashboard/templates/base.html
 M dashboard/templates/incident_detail.html
 M detections/entra/device_code_auth_success.yaml
MM docs/architecture.md
 M docs/correlation.md
 M docs/detections.md
MM docs/evaluation.md
AM docs/holdout.md
AM docs/phase9-external-evaluation.md
AM docs/phase9b-first-collection-checklist.md
AM docs/real-lab-collection-guide.md
 M pyproject.toml
A  scripts/freeze_holdout.py
AM scripts/ingest_real_export.py
A  scripts/report_by_provenance.py
M  scripts/seed_demo_data.py
 M tests/detection/test_rules.py
A  tests/fixtures/holdout/holdout_v1.json
M  tests/integration/test_evaluation_harness.py
MM tests/integration/test_event_pipeline.py
A  tests/integration/test_holdout_runner.py
 M tests/integration/test_incidents.py
AM tests/integration/test_ingest_real_export.py
A  tests/integration/test_report_by_provenance.py
 M tests/unit/test_correlation_loader.py
 M tests/unit/test_detection_loader.py
M  tests/unit/test_evaluation_scenarios.py
A  tests/unit/test_holdout.py
 M tests/unit/test_normalizers.py
?? correlations/admin_consent_bridge_same_user.yaml
?? detections/entra/admin_consent_required_signin.yaml
?? docs/evidence-pack.md
?? docs/evidence/01-real-a2-workflow.png
?? docs/evidence/02-a2-benign-twin.png
?? docs/evidence/03-real-atomic-alerts.png
?? docs/evidence/04-final-real-metrics.png
?? docs/evidence/05-provenance-breakdown.png
?? docs/evidence/06-tests-and-lint.png
?? docs/evidence/architecture-diagram.png
?? docs/evidence/raw-to-detection-proof.md
?? docs/release-files-v1.0.txt
?? docs/release-readiness-v1.0.md
?? docs/release-snapshot-2026-09-22.md
?? evidence_pack/01_raw_vendor_evidence/entra_revocation_audits.redacted.json
?? evidence_pack/01_raw_vendor_evidence/entra_revocation_signins.redacted.json
?? evidence_pack/02_processing_detection_evidence/revocation_incidents_unchanged.json
?? evidence_pack/02_processing_detection_evidence/revocation_matches.json
?? evidence_pack/03_evaluation_results/real_metrics_final.json
?? evidence_pack/03_evaluation_results/report_by_provenance_final.txt
?? evidence_pack/03_evaluation_results/synthetic_and_holdout_final.json
?? evidence_pack/03_evaluation_results/workflow_semantics_final.json
?? evidence_pack/README.md
?? real_data/README.md
?? scripts/collect_entra_telemetry.py
?? scripts/collect_github_telemetry.py
?? scripts/real_metrics_report.py
?? scripts/report_workflow_semantics.py
?? tests/integration/test_correlation_bridged_dashboard.py
?? tests/integration/test_correlation_bridged_pipeline.py
?? tests/integration/test_grant_remove_semantics.py
?? tests/integration/test_real_metrics_report.py
?? tests/integration/test_report_workflow_semantics.py
?? tests/integration/test_workflow_review_semantics.py
?? tests/unit/test_collect_entra_telemetry.py
?? tests/unit/test_collect_github_telemetry.py
?? tests/unit/test_correlation_bridged.py
?? tests/unit/test_db_additive_columns.py
?? tests/unit/test_workflow_review_units.py
```

# Suggested Commit Message

```text
feat: finalize IdentityTrace v1.0 real-telemetry validation

Complete Phase 9B Entra/GitHub lab evaluation and the workflow-review
redesign. Preserve synthetic, multi-seed and frozen holdout evaluation,
including real-data limitations and the benign-twin finding.

Add the redacted evidence pack, screenshots and architecture diagram.
Finalize documentation, scrub private fixture identifiers, exclude private
collection files from Docker context, and align release metadata to 1.0.0.

Validation: 412 tests passed, 97.61% coverage, ruff clean. Synthetic,
holdout, real metrics and provenance reports match saved evidence;
workflow results match after public identifier redaction.
```

# Suggested v1.0.0 Tag Message

```text
IdentityTrace v1.0.0

Identity/SaaS detection, correlation and analyst workflow review with
separate synthetic, frozen holdout and limited real Entra/GitHub lab
evaluation. Includes redacted portfolio evidence and documented
observability, baseline and intent limitations. 412 tests pass,
97.61% coverage, ruff clean. Real workflow findings do not prove compromise.
```

# Exact Manual Commands I Should Run

These are instructions for the owner; they have not been executed.
In PowerShell, review and stage only the explicit manifest:

```powershell
Set-Location (Join-Path $env:USERPROFILE 'Downloads\saas-project\identitytrace')
Get-Content .\docs\release-files-v1.0.txt
git status --short --untracked-files=all
git diff --stat
git diff --cached --stat
git add --pathspec-from-file=docs/release-files-v1.0.txt
git diff --cached --check
git diff --cached --stat
git diff --cached
```

Read the staged diff before proceeding. Then commit and tag locally:

```powershell
git commit -m "feat: finalize IdentityTrace v1.0 real-telemetry validation" -m "Complete Phase 9B Entra/GitHub evaluation, workflow-review redesign and evaluation hardening. Add redacted portfolio evidence and finalize documentation/privacy checks. Align version metadata to 1.0.0. Validation: 412 tests, 97.61% coverage, ruff clean; saved evaluation results reproduced with accepted real-data limitations."
git tag -a v1.0.0 -m "IdentityTrace v1.0.0: identity/SaaS detection, correlation and analyst workflow review. Separate synthetic, frozen holdout and limited real Entra/GitHub evaluation; redacted portfolio evidence and explicit observability/intent limitations. 412 tests pass, 97.61% coverage, ruff clean."
git status --short
git show --stat --oneline HEAD
git show --no-patch v1.0.0
```

No push command is included. The tag marks the commit created above.

# Ready for My Final Commit?

**Yes, for your review and manual commit/tag.** The accepted v1.0 scope is
closed, the checks above pass, and limitations remain visible. This is a
release-readiness finding, not a claim of enterprise readiness or an
independent security audit. No git mutation was performed by this pass.
