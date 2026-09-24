# Pre-release snapshot — 2026-09-22

> Historical snapshot, superseded for release readiness by
> [the final v1.0 review](release-readiness-v1.0.md). Its git counts and
> missing-screenshot status describe September 22, not the final state.
> Six screenshots and an architecture diagram now exist in `docs/evidence/`.
> The final privacy pass also replaced real identifiers in test fixtures.


Taken before any commit or tag, at the user's request, after research scope
was frozen (real revocation experiment closed the last open semantic
question). This is a record of exact state, not a go/no-go decision - the
user reviews it before anything is committed.

## 1. Full test count

```
412 passed, 2 warnings in 58.23s
```
Command: `.venv/Scripts/python.exe -m pytest -q`. The 2 warnings are a
third-party deprecation notice (`starlette.testclient` / `anyio`), not a
project defect.

## 2. Ruff / lint status

```
All checks passed!
```
Command: `.venv/Scripts/python.exe -m ruff check .`

## 3. Final synthetic results

Seed-42 single run:
- Isolated rules: recall 1.000, precision 0.596, F1 0.747, FPR 0.239
- Correlation: recall 0.833, precision 1.000, F1 0.909, FPR 0.000

Multi-seed (seeds 10/20/30/40/50, 8 scenarios/type), aggregated:
- Isolated rules: recall mean 1.000, precision mean 0.855 (stdev 0.000)
- Correlation: recall mean 0.829 (stdev 0.009), precision mean 1.000, FPR
  mean 0.000

Per-seed breakdown (unaggregated): `evidence_pack/03_evaluation_results/synthetic_and_holdout_final.json`.

## 4. Final holdout results (frozen holdout, never edited)

- Totals: 21 attack scenarios, 106 benign events, 17 benign sequences, 48
  malicious events, 73 atomic alerts, 18 incidents.
- Isolated rules: recall 1.000, precision 0.712, F1 0.832, FPR 0.198.
- Correlation: recall 0.857, precision 1.000, F1 0.923, FPR 0.000.
- Alert-reduction ratio: 4.06.
- Per-scenario correlated recall: A1-A5 and COMBO 1.0; **A6 0.0**
  (documented pre-existing gap, unrelated to this work).

Identical to every snapshot taken since the workflow-review redesign - 0
structural differences across the grant-delta fix, the `IDT-CORR-006`
reclassification, the Remove-grant normalization, and the real revocation
experiment. None of those changes touch what the holdout's fixtures exercise.

## 5. Final real results

Full real corpus (227 original + 11 revocation-experiment events = 238
total; `real_metrics_report.py`):

| | Isolated rules | Correlation |
|---|---|---|
| Recall | 1.000 | 0.286 (2 of 7 exports; 1 of 3 real A2 attempts) |
| Precision | 0.575 (23 TP / 40 alerts) | 0.500 (1 TP incident / 2) |
| F1 | 0.730 | 0.364 |
| False-positive rate | 0.081 (17 FP / 209 benign events) | 0.143 (1 FP incident / 7 benign files) |
| Alert-reduction ratio | n/a | 20.0 (degenerate - see docs/evaluation.md) |

Workflow semantics (`report_workflow_semantics.py`), the two `IDT-CORR-006`
incidents:
- **Attack-detector view**: 1 true positive, 1 false positive -> precision
  0.500 (the original result, preserved unchanged as evidence the rule
  cannot infer intent).
- **Workflow-detector view**: 2 of 2 confirmed from raw vendor fields ->
  precision 1.000; malicious intent unresolved; 0 incidents carry
  independent escalation evidence.

Full detail: `evidence_pack/03_evaluation_results/real_metrics_final.json`,
`workflow_semantics_final.json`, `report_by_provenance_final.txt`.

## 6. Screenshots / evidence inventory

- **Present**: `evidence_pack/01_raw_vendor_evidence/` (2 files, redacted),
  `02_processing_detection_evidence/` (2 files), `03_evaluation_results/`
  (4 files). `docs/case-studies.md` (2 full incident narratives, existing).
- **Missing, and why**: screenshots and a demo GIF/video (blueprint
  §14.1). No browser-automation tool is available in this environment, so
  they cannot be captured here. `docs/evidence-pack.md` lists the exact 5
  screenshots still needed and where to add them
  (`evidence_pack/04_screenshots/`, not yet created).

## 7. Generated machine-readable result files

All under `evidence_pack/`, this run:
- `03_evaluation_results/synthetic_and_holdout_final.json` - seed-42,
  5 multi-seed runs, frozen holdout (via `app.evaluation.harness` /
  `holdout_runner`).
- `03_evaluation_results/real_metrics_final.json` - `scripts/real_metrics_report.py`
  output over every `real_data/*.provenance.json`.
- `03_evaluation_results/workflow_semantics_final.json` - `scripts/report_workflow_semantics.py`.
- `03_evaluation_results/report_by_provenance_final.txt` - `scripts/report_by_provenance.py`.
- `02_processing_detection_evidence/revocation_matches.json`,
  `revocation_incidents_unchanged.json` - direct SQL dumps against the
  live app database.
- `01_raw_vendor_evidence/entra_revocation_{audits,signins}.redacted.json` -
  redacted real vendor exports.

## 8. Git status / diff summary

Repository has one prior commit
(`4308c1d feat: complete IdentityTrace v1 with detection, correlation,
evaluation, CI, and real-schema validation`) and a large amount of
Phase 9B+ work never committed since, per this project's standing rule of
only committing when asked. Current working tree, by status code:

| Status | Count | Meaning |
|---|---|---|
| `M ` / `MM` | 28 | modified, some staged some not, some both |
| `A ` / `AM` | 15 | new file, staged (some also modified since staging) |
| `??` | 18 | new file, not staged |

Diffstat: staged changes = 28 files, +6743/-205 lines. Unstaged changes =
33 files, +2778/-167 lines. Nothing has been committed or tagged.

**No action taken on git state** - staging is left exactly as found; this
snapshot does not add, restage, or commit anything.

## 9. Secret / credential scan result

- Pattern scan (AWS-style keys, `client_secret`, PEM private-key headers,
  hardcoded `password =`, raw `Bearer <token>`) across every tracked file,
  every staged diff and every unstaged diff: **zero matches**.
- `real_data/` (raw vendor exports, real tenant identifiers) and
  `.entra_token_cache.json` (live credential cache) are both gitignored;
  confirmed with `git check-ignore -v` and `git add -n real_data` (only
  `real_data/README.md` would be added).
- No `.db` file is tracked or staged.
- Nothing in this evidence pack contains an access token, client secret,
  or the unredacted tenant domain/IP addresses (verified after redaction).

## Not covered by this historical snapshot

Screenshots, demo video, and the git commit/tag itself - all deliberately
left for the user's review and action, per instruction.
