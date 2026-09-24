# Evidence Pack & Portfolio Proof

Satisfies blueprint §14.1/§14.2 (public README, screenshots, reproducible
fixtures, an honest evaluation report, case studies) by organizing what this
project has actually produced into three evidence tiers, each kept separate
so a reviewer can tell *what was observed* from *what IdentityTrace did with
it* from *what that measured*. Nothing here is fabricated: every file is
either a real vendor export (redacted for IPs/tenant-personal identifiers
per §13), a real query result against the app's own database, or a real run
of the evaluation harness/scripts already in this repo.

Prepared under `evidence_pack/` for inclusion in v1.0 (redacted/derived
data - the raw, unredacted exports stay in the gitignored `real_data/`).
Synthetic and holdout results reproduce from the public checkout. Real
reports require the private exports/provenance and populated lab database;
public evidence alone does not reconstruct that private corpus. Run the
reporting commands below against a disposable database copy.

## Tier 1 — Raw vendor evidence

Public copies of real Microsoft Graph telemetry, with tenant domains,
IPs, tenant-specific object/service-principal IDs, and event/correlation
IDs replaced by placeholders. Lab identity names such as `idt-admin` and
`idt-test-user1` remain. Public Microsoft application IDs are retained
because they identify shared applications, not this tenant.
These are anonymized evidence copies, not byte-identical raw exports.
The existing redaction also replaced dotted version strings in some
`userAgent` values; those fields cannot support client-version analysis.
Unchanged private vendor exports remain in `real_data/`.

Placeholder names differ between some screenshot and JSON artifacts;
they preserve each artifact's relationships but are not a universal join
key across the evidence pack. Metrics and workflow semantics are preserved.

- `01_raw_vendor_evidence/entra_revocation_audits.redacted.json`,
  `entra_revocation_signins.redacted.json` - the real revocation experiment
  (see "Real revocation experiment" below).
- Full corpus (unredacted, gitignored): `real_data/*.json` +
  `*.provenance.json`, collected via `scripts/collect_entra_telemetry.py`
  and `scripts/collect_github_telemetry.py`.

## Tier 2 — IdentityTrace processing/detection evidence

What the pipeline (`app/pipeline.py`: normalize -> baseline -> detect ->
correlate) actually did with Tier 1 input - which rules fired, which did
not, what score and evidence an incident carries. Queried straight from the
app's own tables (`events`, `detection_matches`, `incidents`), not
recomputed or summarized by hand.

- `02_processing_detection_evidence/revocation_matches.json` - proof of a
  negative: all 8 grant events from the revocation experiment, the
  permissions IdentityTrace extracted from each, and the resulting
  detection matches (zero).
- `02_processing_detection_evidence/revocation_incidents_unchanged.json` -
  both `IDT-CORR-006` incidents (real attack + benign twin), dumped after
  ingesting the revocation experiment, to show they are byte-identical to
  the pre-experiment state.
- `docs/case-studies.md` - two full incident walkthroughs from
  `GET /api/incidents/{id}`, unedited (existing deliverable, referenced
  here rather than duplicated).

Reproduce: `python scripts/ingest_real_export.py <file> --source entra
--label real_benign`, then query `/api/incidents` and
`/api/events/{id}/deviations` on the running app.

## Tier 3 — Evaluation/results evidence

Metrics, computed by the same tested `compute_metrics()` for both synthetic
and real data (see docs/evaluation.md's own emphasis on this) - never
computed a second, different way for a nicer number.

- `03_evaluation_results/synthetic_and_holdout_final.json` - seed-42 single
  run, all five multi-seed runs, and the frozen holdout.
- `03_evaluation_results/real_metrics_final.json` - full metric set against
  every real provenance file (`scripts/real_metrics_report.py`).
- `03_evaluation_results/workflow_semantics_final.json` - `IDT-CORR-006`
  under both semantics, attack-detector and workflow-detector
  (`scripts/report_workflow_semantics.py`).
- `03_evaluation_results/report_by_provenance_final.txt` - per-file benign/
  attack sanity check (`scripts/report_by_provenance.py`).
- `docs/evaluation.md` - the narrative this data supports, including every
  documented limitation.

---

## Real revocation experiment, as portfolio evidence

Research scope was frozen 2026-09-22 after this experiment (see
docs/evaluation.md, "Real revocation experiment: how Entra logs a genuine
permission reduction"). What it demonstrates, for a reviewer who will not
read the full evaluation doc:

1. **Entra used the same Add + Remove pair structure for both an ordinary
   update and a genuine scope reduction.** Four pairs observed total (one
   consent growth, two reductions, one earlier update from the twin
   collection) - identical shape in all four: same `correlationId`, actor,
   IP and `targetResources`; differing only in `activityDisplayName`,
   `operationType` (`Assign`/`Unassign`) and a 1-2 ms timestamp offset. See
   Tier 1's redacted export.
2. **Permission direction had to be derived from the old/new scope delta,
   not the event name.** The event named `Add delegated permission grant`
   was, in both reductions, the one that *removed* `Mail.ReadWrite` (13
   scopes -> 12). Only comparing `oldValue` and `newValue` reveals that.
3. **The current implementation correctly produced zero grant alerts for
   the reduction** - see Tier 2's `revocation_matches.json`: all 8 grant
   events, zero `IDT-ENTRA-001`/`-002` matches, even though `Files.Read.All`,
   `Mail.Read` and `offline_access` all remained in the grant afterward.
   Scored on the pre-fix cumulative model, the same 8 events would have
   produced 16 alerts (counterfactual, not a claim about shipped behavior).
4. **The experiment did not change incident/correlation behavior.** Both
   `IDT-CORR-006` incidents (the real attack and its benign twin) are
   byte-identical before and after ingesting the revocation export - same
   scores (75/high), same evidence, same confidence. See Tier 2's
   `revocation_incidents_unchanged.json` and Tier 3's before/after table in
   docs/evaluation.md.

### The failed-revocation observation - documented carefully

One `revoke-scope` API call returned `400 Permission being updated or
deleted is not found` (a replication race the experiment's own prior write
had triggered), yet the directory audit log still contains an Add + Remove
pair timestamped at that call recording the same reduction. The change did
**not** persist - the next successful call still saw the scope present.

This is reported as **a single observed case**, not a general property of
audit logging: **it is not claimed that audit logs generally fail to
represent state.** One instance, one tenant, one specific replication
condition; the mechanism is not established. The practical implication
kept in the docs: **verifying an operation's final effect may require
checking the actual resource state (here, `GET /oauth2PermissionGrants/{id}`)
in addition to the audit event**, not the audit trail alone. No detection or
correlation logic was changed on the basis of this one observation, and no
new alerting behavior was proposed from it.

---

## Screenshots and architecture diagram

Six public screenshots and one architecture diagram are present under
[`docs/evidence/`](evidence/), linked from the README:

1. `01-real-a2-workflow.png` - controlled A2 workflow, graph and timeline.
2. `02-a2-benign-twin.png` - legitimate approval triggering the same rule.
3. `03-real-atomic-alerts.png` - atomic alert queue.
4. `04-final-real-metrics.png` - real-data metrics output.
5. `05-provenance-breakdown.png` - per-export provenance report.
6. `06-tests-and-lint.png` - recorded 412-test and lint result.
7. `architecture-diagram.png` - implemented pipeline and evaluation paths.

These are redacted presentation artifacts, not additional observations.
`raw-to-detection-proof.md` is the eighth file in that directory, a text
trace rather than a screenshot. The architecture image summarizes the
components; `app/pipeline.py` and `docs/architecture.md` define execution.

The provenance screenshot reports incident participation per export. The
same benign-twin incident appears in both audit and sign-in exports, so
its total of two FP incident memberships is **one unique incident**. The
real metric report deduplicates incidents and reports one FP, precision
0.500 and FPR 0.143. Seven attack exports represent five attempts, not
seven independent runs; the report's legacy "runs" label means exports.

## Not included, and why

- Unredacted `real_data/` - gitignored by design; real tenant IDs, emails,
  IPs must never be committed (blueprint §13).
- `.entra_token_cache.json` - gitignored; a live credential cache.
- A demo video/GIF is not included. It is an accepted presentation
  omission for v1.0; the six screenshots are available.
