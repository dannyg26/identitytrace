# Evaluation

Answers the project's research question with reproducible numbers, not
assertions:

> Can cross-event identity correlation reduce alert fragmentation and
> improve investigation context while maintaining useful detection
> coverage against realistic benign and malicious activity? Can
> behavioral and temporal correlation distinguish malicious identity
> chains from isolated legitimate events more effectively than atomic
> rules alone?

## Five validation tiers

Every claim below is labeled by which of these it rests on. They are not
interchangeable, and later results build on earlier ones rather than
replacing them.

| Tier | What it checks | Where |
|---|---|---|
| 1. Unit validation | Component correctness against this project's own fixtures | `tests/unit/`, `tests/detection/` |
| 2. Real schema validation | Field names/shapes checked against Microsoft/GitHub's real published API docs | [`normalizer-fidelity.md`](normalizer-fidelity.md) |
| 3. Live lab telemetry | Real Entra/GitHub logs from a real (lab) tenant/org, ingested unmodified | [`phase9b-first-collection-checklist.md`](phase9b-first-collection-checklist.md) - **real Entra and GitHub corpus collected and evaluated; see below** |
| 4. Mixed evaluation | Synthetic attacks/noisy benign, frozen holdout, and real telemetry run through the identical pipeline and reported separately | This document |
| 5. Public background data | BOTS v2/v3 or similar, as ambient noise | **Not pursued** - both are Splunk-index-only distributions requiring a running Splunk instance; see [`normalizer-fidelity.md`](normalizer-fidelity.md) |

## Study scope

The controlled real-telemetry study contains 238 labeled events (213 Entra,
25 GitHub), including three A2 attempts, two A4 attempts, one benign twin,
and a revocation experiment. Synthetic, frozen holdout, and real results
remain separate. No public external dataset was integrated.

Collection duration, identity count, fully observed workflows, GitHub visibility,
and baseline history remain limited. A workflow finding does not prove malicious
intent; these results do not establish enterprise generalization. See the
[dataset and limitations](../README.md#dataset-and-limitations) and
[validation record](validation.md).

The sections below preserve the experiment history. Intermediate counts describe
their observation periods; the final real-metrics table reports the combined corpus.

## Design (Tier 4, synthetic)

- **Fixed seed, reproducible.** `run_evaluation(seed=42, ...)` always
  produces the same dataset and the same metrics.
- **Runs the real pipeline.** Every generated event goes through
  `app.pipeline.process_event()` - the identical code the live API calls.
- **Never touches live data.** Each run creates a fresh in-memory SQLite
  database, uses it, and discards it - verified in
  `tests/integration/test_event_pipeline.py::test_evaluation_api_and_dashboard`.
- **Ground truth lives outside the pipeline** (blueprint §10.1.3).
- **Twelve benign sequence types**: a routine-employee population, plus
  six deliberately noisy personas (traveling user, legitimate
  administrator, developer API burst, new corporate laptop, service
  account, legitimate bulk download) and four "ambiguous singleton"
  cases (one isolated new-device/OAuth-consent/repo-access/bulk-download
  signal each, nothing before or after) - see `app/evaluation/scenarios.py`.
- **Six attack families** (A1-A6), each satisfying one correlation rule
  by construction, except A6 (deliberately not - see below).

## The comparison that matters

For every attack scenario instance: did *any* Phase 2 atomic match fire
on a malicious event (isolated-rule baseline), and did a Phase 4 incident
form that includes one as evidence (correlation engine)? "Alerts" for the
isolated baseline are individual `DetectionMatchRecord` rows; for
correlation they're `IncidentRecord` rows.

## Results (single run, seed 42, 2 instances/type)

```
                      recall   precision   f1     FPR     avg latency
isolated rules         1.00      0.596    0.747   0.239      150s
correlation engine     0.833     1.00     0.909   0.0        510s

totals: 12 attack scenarios, 88 benign events (15 sequences),
        26 malicious events, 52 atomic alerts, 10 incidents
alert reduction: 5.2x
```

**This is the actual headline finding, and it only appeared once the
benign dataset stopped being too clean.** An earlier version of this
report used a thin benign population and got isolated-rule precision =
1.00 - a result that proved nothing about why correlation matters, since
there was nothing for either layer to get wrong. With six realistic
noisy personas added (an administrator's routine role changes, a
developer's legitimate repo-access burst, a new laptop, ...), isolated
rules correctly - not as a bug - fire on several of them, and precision
drops to 0.596. **Correlation holds precision at 1.00 on the exact same
dataset.** That contrast, not either number alone, is the finding -
locked in as a permanent regression test:
`tests/integration/test_evaluation_harness.py::test_correlation_is_a_meaningfully_stronger_baseline_under_realistic_noise`.

Read honestly:

- Isolated rules detect faster (many scenarios at 0s latency - the first
  malicious event trips a rule immediately) but pay for that speed in
  false positives once real-looking benign noise exists.
- Correlation is slower by construction (it can only report once the
  *whole* sequence has happened) but F1 (0.909 vs. 0.747) still favors it
  on this dataset.
- **A6's recall gap is real and by design, not hidden.** A6 (SaaS data
  theft) is generated as a standalone bulk-transfer signal with no
  preceding chain - no correlation rule matches a single signal (all five
  require 2+ steps, by design). Isolated rules catch it every time;
  correlation, honestly, never forms an incident for it alone. A
  correlation rule was deliberately **not** added to force this to 100% -
  that would weaken the evaluation by hiding a genuine architectural
  boundary (not every meaningful security event is part of a multi-stage
  chain) behind a manufactured pass. See `app/evaluation/scenarios.py`'s
  `_make_a6` docstring.

## Scenario coverage

| Scenario | Isolated recall | Correlation recall |
|---|---:|---:|
| A1 | 100% | 100% |
| A2 | 100% | 100% |
| A3 | 100% | 100% |
| A4 | 100% | 100% |
| A5 | 100% | 100% |
| A6 | 100% | **0%** (by design) |

## Multi-seed results (5 seeds, 8 instances/type - `run_multi_seed_evaluation`)

```
                      recall            precision   f1                FPR     latency
isolated rules      1.000 ± 0.000       0.855       0.922 ± 0.000     0.169     133s ± 8s
correlation engine  0.829 ± 0.009       1.000       0.906 ± 0.006     0.000     520s ± 15s

alert reduction: 3.64x ± 0.04
```

**Honest limitation of this variance report**: isolated-rule precision/FPR
show *zero* stdev across seeds - not because the metric is trivially
stable, but because which specific ambiguous atomic signals fire from the
noisy benign personas is currently structurally fixed (same actions, same
thresholds), not randomized. Correlation recall and both layers' latency
*do* show real seed-to-seed variance, driven by the attack generators'
randomized timing (`rng.randint` calls affecting whether a correlation
window's margin is crossed). Randomizing which noisy-persona actions fire
(not just their timing) would be a legitimate next step if tighter
variance estimates on the precision/FPR side are needed - noted here
rather than let the flat 0.000 stdev read as more rigorous than it is.

Reproduce: `python -c "from app.evaluation.harness import
run_multi_seed_evaluation; import json; print(json.dumps(
run_multi_seed_evaluation(seeds=[10,20,30,40,50], scenarios_per_type=8),
indent=2))"`.

## Frozen holdout results (Tier 4, out-of-sample)

A separately-seeded, separately-composed dataset - including a benign
persona (`shared_workstation`) and an attack combination (`COMBO`: new
device/country -> role assignment -> sensitive access) that exist
*nowhere* in the main generator - frozen once and never edited to improve
scores. Full discipline and the permanent result log:
[`holdout.md`](holdout.md).

First run: isolated recall 1.00, correlation recall 0.857 (same A6 gap,
reproduced out-of-sample), correlation precision 1.00 (zero false
positives on genuinely unseen benign variety), F1 0.923 vs. 0.832. The
novel `COMBO` attack was caught by **both** layers - a positive,
non-trivial result: `IDT-CORR-003`'s sequence matching generalized to a
chain shape it was never specifically written for.

## What this does and doesn't prove

**Does**: on a labeled dataset this project fully controls - now
including realistic ambiguous noise, not just clean signal - correlation
reduces alert volume and holds precision where isolated rules degrade,
across multiple seeds and on held-out data the detector was never tuned
against.

**Doesn't**: generalize to real-world telemetry the rules weren't
designed with in mind (the real lab round below is narrower evidence), or claim
statistical significance beyond this lab dataset (blueprint's explicit
non-goal, §3.2).

**A narrower, complementary check that *was* done**: every normalizer was
validated against fixtures shaped like each source's real API schema -
found and fixed four real bugs. Doesn't change any number on this page (a
schema-fidelity check, not a new detection dataset) but is real evidence
the parsers would survive contact with an actual export. See
[`normalizer-fidelity.md`](normalizer-fidelity.md).

## Methodology notes

- "Isolated-rule" false positives/precision count only Phase 2
  `DetectionMatchRecord`s - Phase 3 baseline deviations aren't "rules" in
  the blueprint's L1 sense, so excluded from that specific comparison.
- Correlation-layer false-positive *rate* (Phase 9 #12) uses benign
  *sequences* as its denominator, not raw events - one persona's full
  activity is one trial, matching how an analyst would actually think
  about "did this identity's activity get wrongly escalated."
- Detection latency is measured from a scenario's first malicious event's
  timestamp to the earliest qualifying alert/incident timestamp.
- A false-positive incident is one whose evidence contains no malicious
  event at all; a mixed incident counts as a true positive.
- Precision/recall/F1 avoid the trap of "IdentityTrace achieves 100%
  precision" as a bare claim - every number here is qualified by exactly
  which tier and which dataset it came from.

## Real vendor telemetry (Tier 3/4) - experiment history

The original Phase 9B plan followed Phase 9A with a first real batch
(target: 3-5 lab identities, 100-500 real Entra events, 100-500 real
GitHub events, and controlled suspicious sequences). The experiments
below record what was actually collected and observed. The accepted
v1.0 endpoint does not require meeting every original collection target. See
[`phase9b-first-collection-checklist.md`](phase9b-first-collection-checklist.md)
for the concrete steps and
[`phase9-external-evaluation.md`](phase9-external-evaluation.md) for the
9A/9B split this reflects.

`scripts/report_by_provenance.py` reports those results segmented by
`real_benign` / `real_controlled_attack` - **never** silently combined
with the synthetic numbers above, and **not expected to match them**:
real logs are messy, and a real result showing worse precision/FPR than
the synthetic run is a stronger, more credible finding than a second
perfect score.

### First real batch (2026-09, Entra only - partial, not Phase 9B complete)

Collected via `scripts/collect_entra_telemetry.py` against a real
Microsoft Entra ID tenant (Entra ID P2 trial, for sign-in log access):
3 real test identities, real interactive sign-ins, a battery of real
admin actions (user creation, profile update, app registration, role
assignment), and one real controlled attack sequence (A2 - broad-scope
OAuth consent: device-code sign-in as a test user requesting
`Files.Read.All`, which required - and got - a real admin-consent grant
from `idt-admin`). GitHub collection remains outstanding; Phase 9B is
**not** complete.

```
real_benign exports: 2
  entra_benign_day1_signins.json: 34 events, 0 false-positive alerts, 0 false-positive incidents
  entra_benign_day1_audits.json:  144 events, 3 false-positive alerts, 0 false-positive incidents
  TOTAL: 178 events, 3 FP alerts, 0 FP incidents (FP incident rate: 0.000 per export)

real_controlled_attack exports: 2 (A2)
  entra_a2_attack_signins.json: isolated=MISSED, correlated=not correlated
  entra_a2_attack_audits.json:  isolated=detected, correlated=not correlated
  Isolated-rule recall:    50.0% (2 runs)
  Correlation-engine recall: 0.0% (2 runs)
```

**Benign FPs**: the 3 alerts are `IDT-ENTRA-006` ("Privileged role
assignment," high severity) firing on 3 genuinely real role/app-role-grant
actions from `seed-benign` - not a bug. The rule is explicitly designed
to flag any role/privilege-assignment event, since that mechanism is
exactly how a compromised identity escalates; it correctly fired on real
privileged actions, and the correlation engine correctly did **not**
escalate any of them into an incident (0/144, 0/34) since no surrounding
suspicious sequence existed.

**Attack recall**: the sign-in export was genuinely missed - the only
sign-in event captured was the pre-consent attempt itself
(`errorCode 90094: Admin consent is required`), not a distinct
post-consent success event (Entra either correlates them under one entry
or the second hadn't propagated by export time) - no rule targets a
single failed sign-in in isolation, correctly. The audit export was
detected (`IDT-ENTRA-001` risky-scope, `IDT-ENTRA-002` offline_access) -
but only after fixing two real normalizer bugs (below); before the fix,
both real controlled-attack exports were missed entirely. Correlation
did not fire on either - correctly: a correlation rule needs a *chain*
of signals, and this run produced exactly one isolated match with no
surrounding sequence to chain against (the resource-access follow-up
step failed - see below). This is not evidence correlation doesn't
work; it's evidence a single-signal attack run can't exercise the
correlation layer at all, which is itself a real, useful finding about
what a *meaningful* controlled-attack sequence needs to contain.

Together, this is the first real-telemetry confirmation of this page's
core synthetic finding - isolated atomic rules are noisy on benign data
and imperfect on attack data considered alone; precision and recall
both depend on correlation - holding on genuine tenant data, not just
synthetic.

Four real bugs were found and fixed by this run, not worked around:

1. `app/normalizers/entra.py`'s audit normalizer crashed on a real
   directoryAudit event initiated by an application rather than a user
   (`initiatedBy.user` explicitly `null`, not merely absent -
   `dict.get("user", {})` doesn't guard against that).
2. `scripts/collect_entra_telemetry.py` used `signIns`' timestamp field
   name (`createdDateTime`) for `directoryAudits` too, which actually
   uses `activityDateTime` - Graph returned a 400 until the query was
   split per endpoint.
3. The real audit event that actually carries a newly-granted OAuth
   scope is `"Add/Remove delegated permission grant"`
   (`DelegatedPermissionGrant.Scope`, a space-separated string) - not
   `"Consent to application"` alone, which the normalizer's `is_consent`
   check and permission parser both assumed. This caused a real,
   complete miss of the A2 attack before the fix.
4. `scripts/collect_entra_telemetry.py`'s `attack-sequence` /me/drive
   call to "exercise" a granted scope 400'd with `"Tenant does not have
   a SPO license"` - this bare/trial tenant has no SharePoint/OneDrive
   provisioned at all. Made non-fatal; the sign-in and consent events
   that already happened are unaffected.

One real gap is documented, not silently patched: `"Consent to
application"`'s own `ConsentAction.Permissions` property is sometimes
Entra's internal `"[[Id: ..., Scope: ...]] => [[...]]"` object-dump
text, not valid JSON. An earlier attempt at this fix naively
whitespace-split that text, which happened to accidentally match a rule
via a stray token (`offline_access`) buried in junk like `"ClientId:"` -
a false match for the wrong reason. That's now left unparsed rather
than guessed at (`event.permissions == []` for that property), since
`DelegatedPermissionGrant.Scope` already carries the same information
cleanly whenever this shape shows up paired with it, as it did here.

All four fixes are covered by regression tests
(`tests/unit/test_normalizers.py`).

### GitHub batch (2026-09, same session)

Collected via `scripts/collect_github_telemetry.py` against a real
personal GitHub account (`gh auth login --scopes "repo,read:audit_log"`):
real repo creation, commit, topic, and visibility-toggle actions
(`real_benign`), plus a real decoy-repo access sequence
(`real_controlled_attack`, A4). Exported via the personal security log
(`Settings > Security log > Export > JSON`) - the org audit-log API path
was tried first and confirmed (not assumed) to require GitHub Enterprise
Cloud even with a freshly-created free org and the `read:audit_log`
scope granted; see `docs/phase9b-first-collection-checklist.md`.

```
real_benign exports: 3 (Entra x2 + GitHub)
  entra_benign_day1_audits.json:  144 events, 3 false-positive alerts, 0 false-positive incidents
  entra_benign_day1_signins.json: 34 events,  0 false-positive alerts, 0 false-positive incidents
  github_benign.json:             11 events,  2 false-positive alerts, 0 false-positive incidents
  TOTAL: 189 events, 5 FP alerts, 0 FP incidents

real_controlled_attack exports: 3 (Entra A2 x2 + GitHub A4)
  entra_a2_attack_audits.json (A2):  isolated=detected, correlated=not correlated
  entra_a2_attack_signins.json (A2): isolated=MISSED,   correlated=not correlated
  github_a4_attack.json (A4):        isolated=detected, correlated=not correlated
  Isolated-rule recall:    66.7% (3 runs)
  Correlation-engine recall: 0.0% (3 runs)
```

**Real finding, not a bug**: the personal security log export's own
446-line file was almost entirely the account's actual unrelated
personal history (going back to March) - only 16 of those events were
this session's lab activity, isolated by repo name (`idt-lab-repo1`,
`idt-lab-secret-vault`) and org (redacted here; a real personal GitHub org)
before ingestion.
The rest was deliberately not ingested - it's genuinely real telemetry,
but out of scope for this collection and not something to fold into a
shared dataset without a reason to.

**Real finding, not a bug (attack signal)**: the simulated "decoy-repo
rapid access" pattern left *no distinguishable trail at all* beyond
ordinary `repo.create` + config events - GitHub's personal security log
doesn't record the repo owner's own authenticated reads of their own
content. The only real signal distinguishing the attack export from an
ordinary benign repo creation was the repo's *name*
(`idt-lab-secret-vault`), which `IDT-GITHUB-003` correctly matches on -
this attack was detected for the right reason, but a more thorough
attack sequence (e.g. an actual second identity/token accessing the
repo, or genuine bulk download volume) would exercise more of the
detection surface than this one did.

A fourth real bug (beyond the four above) was found and fixed:

5. `app/normalizers/github.py` classified **every** `repo.*` audit
   action (`repo.create`, `repo.change_merge_setting`,
   `repo.set_default_workflow_permissions`, `repo.add_topic`, ...) as
   `event_type="repo_access"` - not just the literal `repo.access`
   action. Since every action in this real dataset was correctly
   token-authenticated (`gh` CLI's OAuth token), this made
   `IDT-GITHUB-001` ("PAT used for repository access") fire on 8 of 8
   real repo.* benign events - only 2 were real access events. Narrowed
   to classify only `repo.access` (and the clone family) as access
   events; every existing synthetic scenario already used the literal
   `"repo.access"` action string, so this was fully backward-compatible.
   A sixth bug - `oauth_application_id` arriving as a real int, not the
   string `NormalizedEvent.app_id` requires - was found and fixed the
   same way. Both covered by regression tests.

### Summary across both sources

Full metric set, computed by `scripts/real_metrics_report.py` reusing
`app.evaluation.metrics.compute_metrics()` - the exact same tested
formulas the synthetic harness uses. Labeling units and denominators
differ, so sharing formulas does not make the real and synthetic results
directly interchangeable or suitable for a combined headline:

*(Current as of the real revocation experiment - see "A2 Benign Twin — Detection vs Intent" and the Remove and revocation sections below. Re-run the same command after any future change to keep this
honest; earlier states of this table are described in the sections that
caused each change.)*

| Metric | Isolated rules | Correlation |
|---|---|---|
| Precision | 0.575 (23 TP / 40 alerts) | 0.500 (1 TP incident / 2) - the second is the benign twin, see "A2 Benign Twin" |
| Recall | 1.000 (7 of 7 attack exports) | 0.286 (2 of 7 exports - see below: that is **1 of 3** real A2 attempts) |
| F1 | 0.730 | 0.364 |
| False-positive rate | 0.081 (17 FP / 209 benign events) | 0.143 (1 FP incident / 7 benign export files) |
| Avg. detection latency | 0.6s | 141.9s (125.8s and 158.0s for the two exports of the one correlated attempt) |
| Alert-reduction ratio | n/a | 20.0 - **degenerate, do not read as noise reduction**: 2 incidents over 40 alerts (the second is the benign twin). Not comparable to the synthetic 4.06x. |

Per-scenario: A2 (5 exports = 3 real attempts) - isolated recall 1.0,
correlated recall 0.4 by export. A4 (2 real attempts) - isolated recall
1.0, correlated recall 0.0 (2 of the 3 signals its rule needs; the third
is unobservable on this log source - see the observability findings).
Per-provenance breakdown stays in `scripts/report_by_provenance.py`'s
output. Its two benign incident memberships refer to the same twin
incident in two exports; they are not two unique false positives. Its
legacy `runs` label means export files, not independent workflow attempts.
The full metric table above counts unique incidents.

The final corpus contains 209 benign and 29 attack-labeled events.
Seven attack exports represent three A2 attempts and two A4 attempts;
one A2 attempt correlated, while neither A4 attempt completed its chain.
There are two workflow-review incidents: the controlled A2 workflow and
its benign twin. Under attack-label semantics that is one true positive
and one false positive; both workflows are confirmed from raw telemetry,
with malicious intent unresolved and no independent escalation evidence.

This completes the recorded controlled real-data study. The original multi-day
volume targets remain unmet; collection duration and baseline depth are
limitations, and expansion remains future research. Earlier counts
in the experiment history below are retained as dated-stage evidence.

## Real-World Observability Findings

Per-attack-attempt trace of every expected signal in the real controlled
sequences run so far, from generation through correlation. Built from
the actual ground-truth chains this project's own correlation rules
require (`correlations/new_session_to_sensitive_access.yaml` for A2,
`correlations/developer_token_full_chain.yaml` for A4) - not
reconstructed after the fact.

**Reading the classification column**: *collection gap* = our own
script didn't attempt the step; *vendor observability gap* = we
attempted it and the vendor genuinely doesn't expose it (confirmed by
trying, not assumed); *normalization gap* = the raw event existed but
IdentityTrace's parsing was wrong (now fixed); *detection gap* = the
event was normalized correctly but no rule matched it (none found so
far - every real miss traces to collection or observability); *
correlation gap* = telemetry + normalization + atomic detection all
correct, and correlation still failed to chain them (none found so far
either - see the note after each table).

### A2 attempt #1 (Entra, 2026-09-15) - required chain: `new_session_context -> risky_oauth_consent -> sensitive_resource_access`

| Expected signal | Generated? | Present in raw vendor logs? | Normalized? | Atomic rule fired? | Available to correlation? | Final outcome | Classification |
|---|---|---|---|---|---|---|---|
| `new_session_context` (successful device-code sign-in) | Yes - script confirmed a token was acquired | Partial - only the pre-consent **failed** attempt (`errorCode 90094`) appeared within our observation window | Yes (the failed attempt) | No - correctly: `IDT-ENTRA-003` requires `result=success`, and a failed attempt isn't one | No | Never available | **Superseded by attempt #2's finding below** - originally logged as "needs a longer wait"; attempt #2 got the success entry and it *still* didn't fire, for an unrelated and more fundamental reason. |
| `risky_oauth_consent` (admin grants Files.Read.All/offline_access) | Yes | Yes (`Consent to application` + `Add/Remove delegated permission grant`) | **No → Yes** | **No → Yes** (`IDT-ENTRA-001`, `IDT-ENTRA-002`) | Yes | **Detected**, but only after a same-session fix | **Normalization gap (fixed)** - the real scope-grant shape lived in a different property/event than the normalizer assumed. |
| `sensitive_resource_access` (access using the granted scope) | Attempted (`GET /me/drive/root/children`), failed at the API level | No - `"Tenant does not have a SPO license"`; no SharePoint/OneDrive means no resource-access event of any kind can be logged, regardless of which Graph resource is targeted | N/A | N/A | No | Never generated | **Vendor/environment observability gap** - this bare tenant has identity-only premium licensing (Entra ID P2), no M365 workload (Exchange/SharePoint/OneDrive) at all. Structural, not incidental: no Graph resource-read will produce telemetry here without a full M365 license. |
| **`IDT-CORR-001` (the full chain)** | - | - | - | - | **1 of 3 signals ever available** | **Not correlated** | **Not a correlation-engine defect.** With at most one of three required signals ever present, the correlation engine correctly had nothing to chain. No evidence here would justify touching correlation logic. |

### A2 attempt #2 (Entra, idt-test-user2, 2026-09-15) - waited ~20 min before export

This time the export captured a genuine, distinct **success** sign-in
entry (`status.errorCode: 0`), not just the earlier failure - the
propagation-timing question from attempt #1 is resolved. `IDT-ENTRA-003`
*still* did not fire on it, and the reason is decisive, not another
timing question:

| Expected signal | Generated? | Present in raw vendor logs? | Normalized? | Atomic rule fired? | Available to correlation? | Final outcome | Classification |
|---|---|---|---|---|---|---|---|
| `new_session_context` (successful device-code sign-in) | Yes | **Yes - a genuine success entry this time** (`errorCode: 0`) | Yes | **No** | No | Never available | **Vendor observability gap, now precisely identified**: `authenticationProtocol` - the field `IDT-ENTRA-003` matches on - is **absent from every real sign-in event captured in this entire collection round**, all 40 of them, benign and attack, success and failure, with zero exceptions (checked directly, not sampled). This tenant/client (`Microsoft Graph Command Line Tools`, a first-party public client) simply never populates it, even on an interactive, successful device-code sign-in. This is not a propagation issue and would not be fixed by waiting longer or retrying. |
| **`IDT-CORR-001` (the full chain)** | - | - | - | - | Still 1 of 3 (only `risky_oauth_consent`, from the pre-existing tenant-wide consent grant, was available - no new consent event this round since it was already granted) | **Not correlated** | **Still not a correlation-engine defect.** The atomic rule (`IDT-ENTRA-003`) is where this chain actually breaks, on a real, confirmed field-population gap - one layer upstream of correlation. Whether to redesign `IDT-ENTRA-003` around fields Entra actually populates for this flow (e.g. `isInteractive` + `clientAppUsed`, both consistently present) is a real option worth considering - but it's a detection-rule decision for deliberate review, not something to patch reflexively here. |

### A4 attempt #1 (GitHub, 2026-09-15) - required chain: `repo_access -> sensitive_resource_access -> bulk_data_access`

| Expected signal | Generated? | Present in raw vendor logs? | Normalized? | Atomic rule fired? | Available to correlation? | Final outcome | Classification |
|---|---|---|---|---|---|---|---|
| `repo_access` (token access to an ordinary repo first) | **No** - the attack script went straight to the decoy repo | N/A | N/A | N/A | No | Never attempted | **Collection gap** - our own `seed-attack` script's design, not a vendor limitation. Fixed this session: it now accesses an existing normal repo first when `--normal-repo` is passed. |
| `repo_access` (token access to the sensitive-named repo) | Yes - 3 real `gh api` reads (metadata, file contents, commits) | **No** - GitHub's personal security log does not record the repo owner's own authenticated API reads as `repo.access` (or any) event, confirmed by trying it, not assumed | N/A | N/A | No | Never generated | **Vendor observability gap.** Worked around this session (not "fixed," since the vendor limitation stands): `seed-attack` now also toggles the decoy repo's visibility, the one action already proven this session to produce a real `repo.access` entry. |
| `sensitive_resource_access` (any token interaction with a secret/vault-named repo) | Yes | Yes (`repo.create` + 3 config-change events, all on `idt-lab-secret-vault`) | Yes | Yes (`IDT-GITHUB-003`, matches on repo name) | Yes | **Detected** | **None - working as designed.** Matched by name regardless of `event_type`, which is why it caught this even without a real access-type event landing. Worth knowing: this rule would fire identically on a repo merely *named* like a secret store, accessed for entirely innocent reasons - a real, live tradeoff of a name-based heuristic, not something this round's evidence says to change. |
| `bulk_data_access` (clone/download > 100MB) | **No** - `seed-attack` never attempted a clone | N/A | N/A | N/A | No | Never attempted | **Collection gap.** Added an experimental `--clone` flag this session; whether a real personal-account clone produces a distinct, byte-sized log entry at all is still unconfirmed and is the next thing to test, not something to assume either way. |
| **`IDT-CORR-005` (the full chain)** | - | - | - | - | **1 of 3 signals ever available** | **Not correlated** | **Not a correlation-engine defect**, for the same reason as A2: at most one of three required signals was ever present. |

### A4 attempt #2 (GitHub, 2026-09-15) - repeated with the collection-script fix, plus a real clone test

`seed-attack` was extended (this session) to access a normal repo first
and toggle the decoy repo's own visibility - both proven to generate
real `repo.access` entries. Result: 2 of the 3 required signals were
genuinely present this time.

| Expected signal | Generated? | Present in raw vendor logs? | Normalized? | Atomic rule fired? | Available to correlation? | Final outcome | Classification |
|---|---|---|---|---|---|---|---|
| `repo_access` (normal repo, `idt-lab-repo1`) | Yes | **Yes** - 2 real `repo.access` entries | Yes | Yes (`IDT-GITHUB-001`) | Yes | Detected | **None - the earlier collection gap is closed.** |
| `repo_access` (sensitive-named repo, `idt-lab2-secret-vault`) | Yes (visibility toggle) | **Yes** - 2 real `repo.access` entries, correctly timestamped after the normal-repo access | Yes | Yes (`IDT-GITHUB-001`) | Yes | Detected | **None - the earlier vendor-gap workaround succeeded.** |
| `sensitive_resource_access` (name match) | Yes | Yes (6 events on `idt-lab2-secret-vault`) | Yes | Yes (`IDT-GITHUB-003`) | Yes | Detected | None - working as designed, as before. |
| `bulk_data_access` (real `git clone` of the decoy repo, ~15 min later) | Yes - clone genuinely completed (`.git` + `credentials.txt` confirmed locally) | **No** - zero trace in the next export; not one of the 434 newly-visible lines referenced the repo, a clone action, or a byte-transfer figure | N/A | N/A | No | Never generated | **Vendor observability gap, now confirmed by direct test rather than left untested.** GitHub's personal security log does not capture git-protocol clone operations, on top of already not capturing API reads. |
| **`IDT-CORR-005` (the full chain)** | - | - | - | - | **2 of 3 signals present** (up from 1 of 3) | **Not correlated** | **Still not a correlation-engine defect** - now cleanly down to exactly one missing signal, and that signal has been shown, by direct test, not to be obtainable from this vendor surface at all. Testing `IDT-CORR-005` for real would need either the org/Enterprise audit-log API (documents `git.clone` events) or accepting this as a permanent personal-log ceiling. |

**No collection-fixable detection gaps and no correlation gaps were found this round**, except one deliberately-followed-up finding: `IDT-ENTRA-003`'s match field (`authenticationProtocol`) was confirmed never populated by this tenant/client. That finding was flagged, not acted on immediately - and was then followed up as its own separate, deliberate, evidence-driven rule revision (below), exactly the discipline the instructions asked for: investigate first, decide the outcome from evidence, only then change the rule. Correlation logic itself was still not touched anywhere in that process.

**IdentityTrace bugs vs. vendor/logging limitations, made explicit:**

| # | Issue | Category |
|---|---|---|
| 1 | Entra audit normalizer crashed on `initiatedBy.user: null` (app-initiated events) | IdentityTrace bug (fixed) |
| 2 | Collection script used the wrong Graph filter field name for `directoryAudits` | IdentityTrace bug (fixed) |
| 3 | Normalizer looked for the OAuth scope grant in the wrong event/property | IdentityTrace bug (fixed) |
| 4 | GitHub `event_type` classification lumped all `repo.*` actions into "access" | IdentityTrace bug (fixed) |
| 5 | GitHub `oauth_application_id` arrives as a real int, not a string | IdentityTrace bug (fixed) |
| 6 | Attack-sequence script crashed instead of tolerating a licensing 400 | IdentityTrace bug (fixed) |
| 7 | No resource-access telemetry possible on an identity-only-licensed tenant | Vendor/environment limitation (structural - requires a full M365 license to ever close) |
| 8 | Personal security log has no owner-self-access trail, and no visibility into git-protocol clones either | Vendor observability gap (both confirmed by direct real-world test; personal-log-specific, may not apply to org/Enterprise audit logs) |
| 9 | `authenticationProtocol` never populated on real sign-ins for this tenant/client | Detection rule revised in response - see below |

## IDT-ENTRA-003 revision: a deliberate, real-telemetry-driven rule change

**Original assumption.** `IDT-ENTRA-003` ("Successful device-code authentication," v1) matched `authenticationProtocol == "deviceCode"` - a field the Microsoft Graph `signIn` resource documents. The design note already anticipated this being weak evidence alone ("scored low on its own... becomes much stronger evidence once correlation chains it with what happens after"), but assumed the field itself would at least be present to weakly contribute.

**Real-world observation.** It never was. Across every real sign-in ingested this round, `authenticationProtocol` was absent - not null, not empty, simply never a key in the response body.

**Evidence from the real corpus (37 sign-ins, not sampled - all of them, individually inspected).** Categorized as controlled device-code attack, real benign device-code sign-in (the exact same underlying mechanism, run for baseline collection), real benign browser sign-in, and real failed sign-ins:

| Field | Attack device-code | Benign device-code (same mechanism) | Benign browser | Failed logins | Discriminative? |
|---|---|---|---|---|---|
| `authenticationProtocol` | absent | absent | absent | absent | No - 0/37 populated |
| `isInteractive` | `True` | `True` | `True` | `True` | No - constant, every event |
| `clientAppUsed` | `'Mobile Apps and Desktop clients'` | **identical to attack** | `'Browser'` | matches whichever app | Separates native-client from browser (0 exceptions) - but **not** attack from benign use of that same mechanism |
| `authenticationRequirement`, `authenticationRequirementPolicies`, `authenticationDetails`, `authenticationProcessingDetails`, `incomingTokenType`, `signInEventTypes` | absent | absent | absent | absent | No - 0/37 for every one of these six fields |
| `appDisplayName`, `resourceDisplayName`, `deviceDetail.operatingSystem` | tracks `clientAppUsed` | **identical to attack** | tracks `clientAppUsed` | varies | Redundant with `clientAppUsed`, equally non-discriminative between attack and benign |
| `conditionalAccessStatus`, `riskLevelAggregated` | `'notApplied'` / `'none'` | same | same | same | No - constant across all 37 |
| `status.errorCode` | `90094` / `0` | `0` / `50199` | `0` | varies | No - the same failure code (`50199`) occurs in both benign and attack device-code attempts |

The honest reading of this table: exactly one field discriminates anything, and what it discriminates is *native-client vs. browser*, not *attack vs. benign* - every benign device-code sign-in generated for baseline collection is field-for-field identical to the attack sign-ins. That's not a data gap; it's structurally true that a lone sign-in event can't carry attacker intent when ordinary automation uses the identical mechanism.

**Revised detection rationale.** This doesn't cleanly fit outcomes A, B, or C as pure alternatives - it's a disciplined version of A. `clientAppUsed` is a real, 100%-reliable, always-populated field, so the *evidence* is strong. But the honest claim it supports is narrower than the original: "native/non-browser client sign-in" (mobile apps, desktop OAuth clients, Windows-integrated auth, and device-code all share this value), not "device-code" specifically. The revision:
- `app/normalizers/entra.py` now falls back to a distinctly-named `auth_protocol = "nativeClient"` (never `"deviceCode"`) when `authenticationProtocol` is absent but `clientAppUsed == "Mobile Apps and Desktop clients"` - the real value takes precedence if a future tenant/API version ever does populate the original field, preserving old behavior exactly for that case.
- `IDT-ENTRA-003` (now v2) matches `auth_protocol == "nativeClient"`. Title and description were corrected to claim only what's provable; severity stays **low**, unchanged - the honest scope reduction, if anything, argues against raising it.
- `isInteractive` was tested and explicitly excluded from the match, not merely left out: it's `True` on all 37 real events with zero exceptions, so it would have added nothing but the appearance of extra evidence.
- History preserved: the original v1 YAML content, and exactly why it stopped working, are quoted in the v2 file's own description rather than only living in this doc.

**Before/after benign false positives** (all 189 real benign events, re-ingested fresh through the revised code so the comparison is apples-to-apples, not just re-queried):

| | v1 (`deviceCode`) | v2 (`nativeClient`) |
|---|---|---|
| FP alerts from this rule | 0 (never matched anything real) | **5** - one per real benign native-client sign-in (5 identities) |
| Total benign FP alerts (all rules) | 5 | 13 |

That +8 total is not all attributable to this revision: +5 is `IDT-ENTRA-003` directly; the remaining +3 (on `entra_benign_day1_audits.json`, from `IDT-ENTRA-002`/`IDT-ENTRA-006`) is a same-session, unrelated `oauth_consent`-normalizer fix finally reaching this file on its first fresh re-ingest since that fix landed - separated out here rather than folded into "the cost of this rule change." The genuine cost of the revision is 5 new low-severity alerts across 189 real events (2.6%) - real noise, exactly as predicted going in, not zero and not overwhelming.

**Before/after A2 detection:**

| | v1 (`deviceCode`) | v2 (`nativeClient`) |
|---|---|---|
| Attempt #1 (only a failed pre-consent sign-in captured) | Missed | Missed (correctly - there is no success event in this file to match) |
| Attempt #2 (a genuine success entry was captured) | Missed | **Detected** - `IDT-ENTRA-003` fires on the real success sign-in, producing `new_session_context` |
| Isolated-rule recall on real A2 attacks | 0/2 runs with a signin file | 1/2 |
| Correlation (`IDT-CORR-001`) | Not correlated | **Still not correlated** - see below |

**Correlation was checked, not touched, and still correctly does not fire.** With `new_session_context` now real, a genuinely new question became answerable: does `IDT-CORR-001` chain it with `risky_oauth_consent`? Checked directly - it doesn't, and the reason is decisive: `risky_oauth_consent` is attributed to `idt-admin@...` (who approved the tenant-wide admin consent), while `new_session_context` is attributed to `idt-test-user2@...` (who signed in). The correlation engine chains signals per-identity by design, and these are two different identities - it correctly has nothing to chain. This is a real, separate finding, not a correlation-engine defect: the blueprint's A2 model assumes one identity performs sign-in, consent, and access as a single self-service chain, but this real attack variant needed admin approval for the requested scope, which structurally splits the consent step onto the admin's identity instead of the victim's. Whether `IDT-CORR-001`'s sequence model should account for delegated-admin-consent chains is a real, worthwhile question for a future deliberate review - exactly like this one was - and nothing about correlation was changed to chase it now.

No rule was tuned to this specific attack payload: the revised match (`clientAppUsed`) is a stable Microsoft Graph enum value used by both the benign and attack device-code sign-ins identically, not anything unique to this session's specific app, tenant, or attack sequence.

## A2 Cross-Identity Correlation Investigation

`correlations/` was not touched anywhere in this investigation. This is
evidence-gathering and a proposed design only.

### Why the single-identity model failed

`IDT-CORR-001` chains signals for one `actor_id`. The real A2 sequence
splits naturally across two: `idt-admin` approves the consent (a
tenant-wide, `AllPrincipals` grant - not an action taken "as" the
requesting user), and `idt-test-user1`/`idt-test-user2` are the
identities that actually sign in. No amount of correlation-window
tuning fixes this while the model requires one `actor_id` throughout -
the two steps are structurally never going to share one.

### Raw-field evidence

Every raw Entra event from both real A2 attempts, checked field by
field - not sampled:

| Candidate link field | Admin consent event (audit) | User sign-in/activity | Same? | Reliable enough for correlation? |
|---|---|---|---|---|
| `servicePrincipalId` / `targetResources[].id` | `sp-demo-001` (on `Consent to application`, and as the 2nd target on `Add/Remove delegated permission grant`) | `sp-demo-001` (signin's own `servicePrincipalId`, both attempt #1 and #2) | **Yes - exact, verbatim** | **On its own: no - see benign collision below. As one part of a richer key: yes.** |
| `appId` | not directly present on audit events (Entra references the app via its service principal object, not the client `appId`, in this resource) | `14d82eec-204b-4c2f-b7e8-296a70dab67e` | Not directly comparable - different ID namespace | No - the audit side doesn't expose this field at all |
| `resourceId` (signin) vs. the *other* `targetResources[].id` on the grant events (`sp-demo-graph`, "Microsoft Graph") | present only on audit | `00000003-0000-0000-c000-000000000000` (Microsoft Graph's universal, cross-tenant application ID) | **No - different ID scheme** (universal `appId` vs. this tenant's instantiated service-principal object ID for the same conceptual resource) | No - would require a lookup/mapping table to equate, not a direct match |
| `homeTenantId` / `resourceTenantId` | not exposed as its own field on `directoryAudit` (audit logs are implicitly tenant-scoped) | `<tenant-id>`, constant | Untestable - can't observe multi-tenant behavior from one tenant | Necessary in a real multi-tenant deployment, but this dataset can't validate it either way |
| `correlationId` | `<correlation-id-1>` (shared across all 3 consent-flow audit events - confirms they're one server-side operation) | `<correlation-id-2>` (user1's signin) / `<correlation-id-3>` (user2's signin) - **different from the audit's and from each other** | **No** | No - `correlationId` is per-API-call, not shared across the admin-approval and sign-in legs of the flow |
| `initiatedBy.user.ipAddress` (audit) vs. signin `ipAddress` | `203.0.113.10` | `203.0.113.20` (both users) | **No** | No, and shouldn't be required anyway - a real attacker approving their own consent would often be at a *different* address than the victim, so requiring IP equality would break the exact case this is meant to catch |
| `status.errorCode` on the *triggering* sign-in | n/a | `90094` ("Admin consent is required...") - **occurs on 0 of 34 real benign sign-ins** | N/A (this is a property of the sign-in alone, not a link field) | **Yes - as the anchor that makes the shared-entity link safe (see recommendation)** |

**The A2 sequence is better modeled as `admin -> application/service principal -> user -> resource`** than `user -> user -> user`. The current model's assumption (one actor throughout) doesn't match what actually happens whenever the requested scope requires admin approval - which, for exactly the kind of high-privilege scope A2 is about (`Files.Read.All`, `offline_access`), is the common case, not an edge case.

### Candidate shared entity, classified

**Outcome: a disciplined version of A.** `servicePrincipalId` is a strong, exact, verbatim shared entity - present on both sides, in both real attempts, with zero ambiguity about whether it's "the same app." But using it *alone*, plus a time window, is not safe - shown directly below with real data, not assumed.

### Benign collision analysis

The tenant's own routine activity - `login`, `seed-users`, `seed-benign`
- generates the exact same `Consent to application` /
`Add delegated permission grant` audit events, for this exact same
`servicePrincipalId`, because every script-driven action in this whole
collection uses one app. Checked directly: 5 such benign consent
events exist in the real benign corpus. For both of the two consent
events checked, **multiple different benign identities have a
successful sign-in for that same servicePrincipalId within 2-14
minutes**:

| Benign consent event (servicePrincipalId `54a000cd...`) | Nearby successful sign-ins, same servicePrincipalId, within 900s (`IDT-CORR-001`'s own window) |
|---|---|
| 2026-09-11T18:47:21Z | `idt-test-user1` (+752s), `idt-test-user2` (+793s), `idt-test-user3` (+831s), `idt-admin` (+588s) |
| 2026-09-11T18:57:09Z | `idt-test-user1` (+164s), `idt-test-user2` (+205s), `idt-test-user3` (+243s), `idt-admin` (+0s) |

A correlation rule keyed on "same `servicePrincipalId` + narrow time
window" alone would chain **every one of these** into a false incident.
This isn't a small edge case - it would fire on completely ordinary
admin/tooling activity essentially every time this collection script
runs, because in this tenant (and in any real org with internal
tools/CI service principals) admins routinely re-consent scopes for
apps that users are also, unremarkably, signed into around the same
time. Same-app-plus-time-window is a weak signal precisely because nothing
about it requires the consent to have been *caused* by that user's
request.

**What actually is rare, and never occurs in this benign corpus**: a
sign-in failing with `errorCode 90094`
("Admin consent is required for the permissions requested by this
application") - occurring on 0 of 34 real benign sign-ins, and on
exactly the one real attack sign-in where the requested scope needed
approval. That failure is the causal anchor the naive design is missing:
it's not just "an admin consented near when a user signed in for the
same app" (common, benign), it's "a user's request for a scope was
*specifically blocked pending admin approval*, and an admin then
granted it" (never observed benign, and exactly what happened in the
real attack).

### Recommended design (not implemented)

A cross-identity link should require, together:
1. A sign-in failure signal for the specific `(actor_id, servicePrincipalId)`
   pair, with `errorCode` indicating admin consent is required (a new
   atomic signal - doesn't exist yet; `IDT-ENTRA-003`'s revision didn't
   add this, and no current rule watches for this errorCode).
2. A `risky_oauth_consent` event for the **same** `servicePrincipalId`,
   `activityDateTime` **at or after** the failure, within a bounded
   window (900s, matching `IDT-CORR-001`'s existing window, is
   defensible - it's already the project's chosen tolerance for "how
   fast is fast enough to be one story").
3. Only then, permit chaining into a subsequent `new_session_context` /
   `sensitive_resource_access` for **the same requesting identity**
   from step 1 - not any identity that happens to use the same app
   afterward. This keeps the "same actor for the back half" discipline
   the current model already has right, while replacing the "same
   actor for the whole thing" assumption with a "same
   (app, requesting-identity) pair, admin bridges the middle step" model.

This is deliberately **not** "same app + time window" - the benign
data above shows exactly why that alone isn't safe - it's "same app +
time window + a specific, real, never-benign-observed trigger
condition on the requesting identity's own failed attempt."

### Is it safe to implement now?

**Not yet**, for two evidence-based reasons, not caution for its own
sake:
- Step 1 requires a **new atomic signal** (a sign-in failing with
  admin-consent-required) that does not exist in `detections/` today -
  this is new detection-surface work, not a correlation-rule tweak, and
  deserves its own deliberate design/test pass rather than being bundled
  into a correlation change.
- The real data only has **half** the closing link: `idt-test-user1`'s
  blocked attempt and `idt-admin`'s consent grant for it are both
  captured and linked by `servicePrincipalId` - but `idt-test-user1`'s
  own subsequent successful sign-in/resource-access was never captured
  (attempt #2 tested a *different* user, `idt-test-user2`, whose
  success had no causal tie back to attempt #1's specific consent - it
  simply reused an already-granted, tenant-wide scope). The design
  above is well-supported by evidence for steps 1-2; step 3 is
  reasoned, not yet validated against a real, fully-closed example.

## A2 End-to-End Real Validation

`correlations/` was not modified anywhere in this validation.

### 1. The missing atomic signal: `IDT-ENTRA-007`

The exact raw field is `status.errorCode == 90094` on the Entra
`signIn` resource (`failureReason`: "Admin consent is required for the
permissions requested by this application"). The detection engine only
resolves top-level `NormalizedEvent` fields (`getattr`, no nested
`raw_event_ref` access), so `app/normalizers/entra.py` now surfaces this
into `action` (`"admin_consent_required"`, replacing the previously
constant `"login"`) rather than adding a new schema field for one narrow
case. `IDT-ENTRA-007` matches only that value. Confirmed directly, not
assumed: present in the real controlled attempt (both the original
`idt-test-user1` block and the new `idt-test-user3` block below); 0 of
34 real benign sign-ins. Severity stays low - being blocked pending
consent is Entra working correctly, not itself malicious; the signal
exists to be a chain anchor, matching the same philosophy as
`IDT-ENTRA-003`. Regression tests in `tests/unit/test_normalizers.py`
and `tests/detection/test_rules.py`.

### 2-3. Re-run with one identity end-to-end, exact timestamps

`idt-test-user1` (attempt #1) and `idt-test-user2` (attempt #2) each
only supplied half the chain - re-checking attempt #1 with a wider
window, even days later, found no distinct success entry for
`idt-test-user1` at all (that specific sub-flow, where the admin
approves via a separate "sign in with that account" link mid-session,
apparently never gets a fresh success entry logged for the original
session). So this validation used a **fresh, not-yet-granted scope**
(`Mail.Read` - confirmed absent from every existing grant before
running) with **one user throughout**, and a **second, independent**
device-code sign-in for the retry rather than relying on the original
session to auto-resume - which is exactly the pattern that logged
cleanly for `idt-test-user2` before.

Real, unmodified timestamps, `idt-test-user3`, all sharing
`servicePrincipalId sp-demo-001`:

| Time (UTC) | Actor | Event | errorCode |
|---|---|---|---|
| 18:17:49 | `idt-test-user3` | blocked sign-in | `90094` |
| 18:18:17 | `idt-admin` | consent-flow intermediate | `65001` |
| 18:18:21 | `idt-admin` | `Consent to application` + `Add`/`Remove delegated permission grant` (scope now includes `Mail.Read`) | - |
| 18:18:22 | `idt-admin` | admin's own sign-in completing the flow | `0` |
| 18:20:23 | `idt-test-user3` | retry, transient | `50199` |
| 18:20:27 | `idt-test-user3` | **successful sign-in** | `0` |

Total elapsed: 2m38s, well inside `IDT-CORR-001`'s existing 900s window.

### 4. Validation table

| Step | Expected event | Present in raw logs? | Normalized? | Atomic signal? | Same servicePrincipalId? | Same requesting user? |
|---|---|---|---|---|---|---|
| 1 | Blocked sign-in | Yes (18:17:49) | Yes | Yes - `IDT-ENTRA-007`, `admin_consent_required` | Yes | Yes - is the requesting user |
| 2 | Admin consent grant | Yes (18:18:21) | Yes | Yes - `IDT-ENTRA-001` + `IDT-ENTRA-002`, `risky_oauth_consent` | Yes | N/A by design - admin bridges this step only |
| 3 | Post-consent successful sign-in, same user | Yes (18:20:27) | Yes | Yes - `IDT-ENTRA-003`, `new_session_context` | Yes | **Yes - same user as step 1** |
| 4 | Downstream resource/session access | **No** - the full exported window (5 signins + 4 audits) contains nothing else | N/A | N/A | N/A | N/A |

### 5. Benign collision re-check, after adding `IDT-ENTRA-007`

Re-ran the entire real benign corpus (189 events) fresh against the
rule: **0 matches**. Total benign false-positive alert count is
unchanged (13, same as before this rule existed) - the new rule adds
real detection surface with zero added noise, exactly as its own
evidence predicted (0/34 benign sign-ins ever had this error code).
Since step 1 alone never occurs benign, the full 3-step sequence
structurally cannot appear in the benign corpus either - not re-derived
by assumption, guaranteed by the same fact.

### 6. Proposed cross-identity correlation (still not implemented)

The evidence now supports the design proposed in the prior
investigation, unchanged: `admin_consent_required` (same actor A, same
servicePrincipalId) → `risky_oauth_consent` (same servicePrincipalId,
any actor - the admin) → `new_session_context` for **actor A again**,
within the existing 900s window. This is now validated end-to-end
against one real, fully-closed example, not reasoned about in the
abstract.

### 7. Honest stopping point

Step 4 (downstream resource/session access) is not observable in this
tenant - confirmed again on this attempt, not newly assumed. No
substitute was invented. The defensible real A2 correlation, if
implemented, should stop at:

```
blocked sign-in -> admin consent (same servicePrincipalId) -> successful post-consent sign-in (same requesting user)
```

not extend through resource access, until a tenant with real M365
workload licensing makes that observable.

Full real numbers after this round (`scripts/real_metrics_report.py`):
isolated recall **100%** (7/7 real attack runs - `IDT-ENTRA-007`
retroactively also detects attempt #1's failure-only file), precision
0.690, F1 0.817, benign FP rate unchanged at 0.069, correlation recall
still 0%.

### A2 Cross-Identity Correlation v2

`IDT-CORR-006` - implemented after the design proposed in the two
sections above was validated end-to-end on real logs. Everything below is
bounded by what that telemetry showed.

**Historical context - the design this does not replace.** `IDT-CORR-001`
(the blueprint's own §16.2 example: `new_session_context ->
risky_oauth_consent -> sensitive_resource_access`, one `actor_id`
throughout) is unchanged and remains correct for self-service consent, and
it is still what the synthetic A2 scenarios and holdout A2 exercise. It
failed on the real admin-consent flow for reasons that are properties of
the flow, not defects in the engine.

**Why the single-identity design failed on real telemetry.**
1. *The chain spans two identities.* When a scope needs admin approval the
   consent is performed by the admin, so `risky_oauth_consent` is
   attributed to `idt-admin` while `new_session_context` belongs to the
   requesting user. A per-identity engine correctly cannot join them.
2. *Its third step is unobservable.* `sensitive_resource_access` needs a
   resource read; the only tenant available has no SharePoint/OneDrive/
   Exchange workload, so no such event can exist there.

**The real evidence that justified the redesign** (details in the two
preceding sections): `servicePrincipalId` appears verbatim on both sides
(the requester's sign-ins and the admin's grant events); `errorCode 90094`
occurs on 0 of 34 real benign sign-ins; and a fresh attempt with one
user throughout (`idt-test-user3`, new scope `Mail.Read`) produced the
full sequence with real timestamps - blocked 18:17:49, admin consent
18:18:21, same user succeeds 18:20:27, one service principal throughout.

**The exact rule.** All must hold, all enforced by the schema/matcher and
each covered by a negative test:

| # | Step | Signal (producing rule) | Actor | Same service principal |
|---|---|---|---|---|
| 1 | requester blocked pending admin consent | `admin_consent_required` (`IDT-ENTRA-007`, `errorCode == 90094` only) | anchor | yes |
| 2 | consent granted | `risky_oauth_consent` (`IDT-ENTRA-001`/`002`) | any (the admin) | yes |
| 3 | the **same** requester succeeds | `new_session_context` (`IDT-ENTRA-003`, requires `result == success`) | anchor | yes |

Each step strictly after the previous; step 1 to step 3 within the
existing 900s window; the incident is attributed to the requester, not the
admin, and every evidence line records who performed it. The admin bridges
the consent step only.

**The role of `servicePrincipalId`.** It is the *link*, not the
discriminator - and treating it as the latter is the mistake the benign
data forbids. Measured on the real benign corpus: a naive "same service
principal, consent then success within 900s" join would have produced
**10 false chains** (3 routine admin consent events x 4 routine
successful sign-ins for that same application). The 90094 anchor is what
separates them - it never occurs benign - and the rule as built produces
**0**. Making it usable required data-model care, each with a regression
test: it is now a first-class normalized field (`events.service_principal_id`,
with an additive-column step so existing dev databases keep working);
the all-zero placeholder GUID that real browser sign-ins carry is treated
as *no entity*, never a match; on real grant events the first
`ServicePrincipal` target is the *resource* (Microsoft Graph), not the
client, so only the explicit `ServicePrincipal.ObjectID` property is used;
and a missing entity fails closed (`None` never equals `None`).

**Why downstream resource access is not required.** It is unobservable in
the only tenant tested, and requiring it would make the rule un-fireable
there. Nothing was substituted for it. The rule claims only the three
observed steps; if a tenant with real M365 workloads later makes resource
access observable, it can be added as a fourth step with its own evidence.

**Before / after, real telemetry.**

| | Before | After |
|---|---|---|
| Real A2 exports correlated | 0 of 5 | 2 of 5 (= **1 of 3** real attempts) |
| Attempt #1 (`user1`): block + consent captured, the user's own success never logged | not correlated | not correlated - **correctly**: no success to close it |
| Attempt #2 (`user2`): success captured, but no block by that user; consent pre-existing | not correlated | not correlated - **correctly**: no block anchor |
| Attempt #3 (`user3`): full sequence | not correlated | **correlated**: 1 incident, `attack_chain` = the three signals, evidence `user3 -> admin -> user3`, one service principal |
| Real correlation recall / precision | 0.0 / n/a | 0.286 (by export) / 1.000 |
| Real benign false-positive **incidents** | 0 | **0** (189 events; atomic alerts unchanged at 13) |
| Total incidents across all real data | 0 | 1 - the correct one; A4 and the two incomplete A2 captures produce none |

The 2-of-7 headline is by export file; the honest unit is the attempt.
Two of three real A2 attempts were *incomplete captures*, and correlating
them would have been wrong, not lucky.

**Order-independent arrival, shown on real data.** Ingesting `user3`'s
sign-ins before the admin's consent audit file left 0 incidents; the chain
completed when the consent arrived. This is deliberate: audit events
propagated minutes before their matching sign-ins, from a different
endpoint. Unlike the existing rules (which only look backward from the
triggering event), this type fetches a full window in both directions and
lets the matcher enforce the real constraints.

**Synthetic and holdout impact: none.** A strict programmatic diff of the
seed-42 single run, all 5 seeds of the multi-seed run (per-scenario detail
included) and the holdout against measurements taken immediately before the
change: 0 differing values. Expected - no synthetic event has a 90094
sign-in or a service-principal entity.

**A pre-existing holdout regression, found while establishing that
baseline (not caused by this change).** The holdout's correlation recall
was already 0.714, not its documented 0.857 (18 incidents -> 15; A2
1.0 -> 0.0). Cause, verified by an in-memory-only patch: the frozen holdout
has exactly 3 payloads with the legacy `authenticationProtocol:
"deviceCode"` and 0 with the real `clientAppUsed` shape, and
`IDT-ENTRA-003` v2 matches only `nativeClient`. Accepting both restores the
documented result exactly. It was missed because the v2 revision was
verified against real data and the test suite but not re-run on the
holdout. Not fixed in that change (out of scope); fixed immediately
afterwards - see "IDT-ENTRA-003 v3" below.

**Scoring note (not tuned).** The incident scores 85 - `critical`, exactly
at the band floor - from 75 of atomic weight (15 + 45 + 15) plus this
rule's `score_bonus: 10`, chosen before the result was seen. The existing
additive model has no way to reflect that no data access was observed;
any bonus of 9 or less would read `high`. Left as an explicit decision.
*(Superseded: the 85 was partly inflated by a cumulative-scope scoring defect and the
rule was later reclassified as a workflow review - the real chain now scores 75 / high.
This note is kept as written; see "A2 Benign Twin — Detection vs Intent".)*

**Limitations that bound the claim.**
- **One fully-observed real instance**, in one tenant, for one application.
  The design was proposed from earlier attempts and this attempt was
  collected afterwards to test it, so it is a genuine prospective check -
  but n = 1. Generalization to other applications is untested.
- **The benign twin is untested and structurally identical.** "User blocked
  -> admin legitimately approves a risky scope -> user succeeds" produces
  this exact chain. Only the risky-scope signal separates it from an attack.
  The 0 false-positive incidents reflect that the benign corpus contains no
  legitimate approval workflow, **not** that such a flow would not fire.
  Its real false-positive rate was unmeasured when this was written; the
  benign twin below has since measured it (it fires, identically).
- **Consent is linked to the block by service principal + order + time
  only.** Entra does not expose that a consent was made *in response to* a
  given block; an unrelated admin consent for the same application inside
  the window would satisfy step 2.
- **Timestamp resolution differs**: sign-ins are whole seconds, audits are
  microseconds. Strict ordering could in principle mis-order a consent and a
  success within the same second (the real gap was 158s).

**Test evidence.** 82 new tests (262 -> 344): engine and schema (43),
end-to-end through the real pipeline including all six arrival orders (25),
normalizer traps (7), database migration (3), API/dashboard attribution
(4). That last group exists because exercising the real incident through
the running app found a gap the data-level tests could not: the incident
*data* named the admin on the consent step, but the dashboard page did not
- an admin's consent would have read as the requesting user's. The page now
marks any step performed by an identity other than the incident's own; single-
identity incident pages are unchanged (regression-tested). The matcher was
mutation-tested - removing each of five safety constraints in turn
(entity equality, actor binding, strict ordering, whole-chain window,
entity-required anchor) fails the suite each time.

### IDT-ENTRA-003 v3: compatibility restoration (not a detection improvement)

**Cause.** The v2 telemetry-model change ("IDT-ENTRA-003 revision" above)
replaced the match on `authenticationProtocol == "deviceCode"` with the
derived `nativeClient` value, because real Entra sign-ins never populated
the original field. That was right for real telemetry, but it also meant
the rule silently stopped honoring a *documented* Graph value that another
tenant or API version may populate, and that the frozen holdout dataset
still carries (3 payloads, one per A2 instance; 0 carry the real
`clientAppUsed` shape). The holdout was not re-run after v2, so the
regression - correlation recall 0.857 -> 0.714, A2 correlated recall 1.0
-> 0.0 - went unnoticed until a later change needed a baseline.

**Fix.** The rule now accepts exactly two equivalent representations of the
same fact, `nativeClient` (v2's real-telemetry representation) and
`deviceCode` (the legacy documented one). Nothing else was broadened:
`interactive`, `basic`, browser sign-ins and every other value still do not
match, the sign-in must still be successful, and severity/score are
unchanged. The cause was verified with an in-memory-only patch before any
file was touched.

**Results** (all measured, each against the state immediately before):

| Check | Result |
|---|---|
| Unit/regression suite | 355 passed (344 + 11 new boundary tests) |
| Holdout correlation recall | **0.714 -> 0.857** - identical to the documented first run on all 17 recorded figures |
| Holdout A2 correlated recall | **0.0 -> 1.0** (only A2-0/1/2 changed) |
| Seed-42 single run | 0 differing values |
| All 5 multi-seed runs (per-scenario detail included) | 0 differing values |
| Complete real-data evaluation (fresh re-ingest of all 10 exports) | 0 differing values: isolated recall 1.0 / precision 0.690 / F1 0.817 / FPR 0.069; correlation recall 0.286 / precision 1.0 / 0 false-positive incidents; 1 incident |

The real corpus is unchanged for a reason worth stating: no real event
carries `authenticationProtocol`, so the restored representation has
nothing to match there. This restores previously-documented behavior for
telemetry that populates the field; it adds no new detection capability on
any data collected so far, and should not be read as one.

**At this stage:** `IDT-CORR-006`'s `score_bonus` remained 10 pending the
benign-twin result. That experiment and the final workflow-review
classification are documented in the following sections.

### A2 Benign Twin: does `IDT-CORR-006` separate a legitimate admin-consent workflow from an attack?

Collected specifically to answer the open limitation recorded in "A2
Cross-Identity Correlation v2" - *before* any change to the rule or its
`score_bonus`. Same mechanism, code path, application (service principal
`54a000cd...`) and one requesting user throughout, on a different day:

| | Attack chain (Sep 15) | Benign twin (Sep 21) |
|---|---|---|
| Requester | `idt-test-user3` | `idt-test-user1` |
| Scope requested | `Mail.Read` | `Mail.ReadWrite` (a *broader* privilege; also on `IDT-ENTRA-001`'s list) |
| Blocked (`90094`) | 18:17:49 | 16:35:17 (and again 16:36:15, same session) |
| Admin consent | +32s | +78s from the first block (+20s from the second) |
| Requester succeeds | +158s from the block | +253s from the first block |
| Fits the 900s window | yes | yes |

**Result: the benign twin triggers `IDT-CORR-006`, and is indistinguishable
from the attack.**

| | Attack | Twin |
|---|---|---|
| Incident | `IDT-CORR-006`, attributed to the requester | `IDT-CORR-006`, attributed to the requester |
| Score / severity | **85 / critical** | **85 / critical** |
| Score breakdown | 75 event risk + 0 deviation + 10 chain bonus | 75 + 0 + 10 (identical) |
| Confidence | 0.85 | 0.81 (slower chain only) |
| Signals | `admin_consent_required` -> `risky_oauth_consent` -> `new_session_context` | identical |

The rule did exactly what it was built to do. The finding is that what it
was built to do does not encode intent: it detects the *workflow* "a
blocked user's risky-scope request was approved by an admin and the user
then succeeded", and a legitimate approval is that same workflow.

**Is there any real telemetry that separates them? Not in what was
collected.** A step-by-step field diff of the two chains (block, grant,
success; every raw field flattened):

- Block: 30 of 40 fields identical. Grant: 49 of 55. Success: 30 of 40.
- Identical, and therefore useless as discriminators: `appId`,
  `servicePrincipalId`, `clientAppUsed`, `userAgent`, `deviceDetail`,
  `isInteractive`, risk levels (`none`), `conditionalAccessStatus`
  (`notApplied`), `ConsentContext.IsAdminConsent`/`OnBehalfOfAll`/`Tags`,
  the audit's `additionalDetails` (user agent, app id, provisioning type),
  `loggedByService`, `category`, `operationType`.
- Everything that differs is an id, a timestamp, the identity itself, or
  an IP/city: the sign-in addresses are neighbouring addresses in the same
  /24 and town, and the audit's initiator address is the one Entra records
  for its own token service (`Azure ESTS Service`), which also differs
  between days. None of that varies with intent. The one substantive
  difference points the wrong way: the twin was granted the *broader*
  scope.
- Timing does not separate them: the twin's chain was slower, but both are
  ordinary human timescales well inside the window.

**What this lab structurally cannot test.** The "attacker", the "admin" and
the "user" are the same person on the same machine, so every discriminator
that depends on the parties being *different* (an admin approving from an
address or device they have never used, a requester on foreign
infrastructure) cannot exist in this data. And both chains use Microsoft's
own first-party application, so application-reputation discriminators
(unverified publisher, recently registered or externally owned app, scopes
disproportionate to the app) cannot differ either - and those live in
directory metadata, not in the sign-in or audit logs collected; the
collector does not request a permission that reads it (untested whether
its current token could, and adding one is a separate permission decision). Entra's formal
admin-consent *request* workflow (request -> review -> approve) may leave
distinct records; it was not exercised, so it is unproven either way.

**A second finding, independent of intent: the risky-scope signal is
driven by scopes that were not part of this event.** `DelegatedPermissionGrant.Scope`
holds the *cumulative* scope string, and both grants merely *added* one
scope (`Mail.Read` / `Mail.ReadWrite`) to a set that already contained
`offline_access`. `IDT-ENTRA-002` (weight 45, the heaviest signal, and the
one the chain selects) therefore fires on `offline_access` granted in an
earlier, unrelated event - for *every* future grant in this tenant,
whatever it adds. Computed on the delta (new minus old) instead, both
chains would carry only `IDT-ENTRA-001` (35), giving 65 + 10 = 75 ("high")
rather than 85 ("critical"), still identical to each other. So the inflated
severity is a partly separable defect, and fixing it would not change the
conclusion above. (Not changed in this section; applied afterwards - see "A2 Benign Twin — Detection vs Intent" below.)

**Real-data effect (twin counted as `real_benign`, as it is).**

| | Before twin | With twin |
|---|---|---|
| Benign events | 189 | 198 |
| Real benign false-positive **incidents** | 0 | **1** |
| Correlation precision | 1.000 | **0.500** (1 true / 2 incidents) |
| Correlation recall | 0.286 | 0.286 |
| Isolated precision / FPR | 0.690 / 0.069 | 0.580 / 0.106 |

(`scripts/report_by_provenance.py` prints "2 false-positive incidents" for
this: the twin's one incident touches both of its export files and that
tool counts per file. The full-metric figure above is the correct one.)

**Recommendation: reclassify `IDT-CORR-006` as a high-risk workflow
requiring analyst review, not a high-confidence attack detection.**
Reasons, from the evidence rather than preference:

1. *It cannot stay a "critical" detection.* Any legitimate approval of a
   risky scope by a blocked user produces a critical-scored incident
   identical to an attack; in a real organisation that is routine, not rare.
2. *Lowering `score_bonus` is not the fix.* The twin and the attack are
   telemetry-identical, so every threshold that suppresses the twin
   suppresses the attack equally. The score cannot carry intent because
   nothing in the chain does.
3. *The linkage is still worth surfacing.* "A user's risky-scope request was
   approved by an admin and the user then succeeded" is exactly the
   privilege-expanding consent event a reviewer should see; the correlation
   is correct and evidence-backed - it is the label "attack" that is not.
4. *Escalation should need an independent discriminator*, none of which the
   current collection can supply: a behavioral deviation on the admin or
   requester (new IP/device/country versus a real multi-day baseline -
   the deviation layer exists, both chains scored 0 because no such history
   was built), or application metadata (publisher verification, app age,
   external ownership) via a deliberate, separate permission decision.

Suggested order, each its own decision: (a) relabel/cap severity for this
rule; (b) score risky scopes on the grant *delta*, not the cumulative
string; (c) collect a multi-day admin/requester baseline so a genuine
deviation could be tested as an escalation gate; (d) test the formal
admin-consent-request workflow for distinct records. When this section
was written nothing above had been applied; (a) and (b) were implemented
next - see "A2 Benign Twin — Detection vs Intent" below. (c) and (d) remain
open.

**Limits of this result.** One twin, one tenant, one application, one
human playing every role - it shows the rule cannot separate intent *on
this telemetry*, not that no telemetry anywhere could.

### A2 Benign Twin — Detection vs Intent

Follows the twin experiment above. That section concluded the rule cannot
separate intent and recommended a reclassification; this one records what
was then implemented, and what was deliberately not.

**Why the benign twin is indistinguishable from the attack in current
telemetry.** Both chains are the same three raw records - a `90094` sign-in
block, an `Add delegated permission grant` audit event by an admin, a
successful sign-in by the same user - for the same service principal,
inside the same window. A field-by-field diff found no field that differs by
intent: what differs is ids, timestamps, the identity itself and an IP/city
that changed between two *days* on one machine. The one substantive
difference (the twin was granted the broader scope) points the wrong way.
The lab cannot even express the discriminators that need the parties to
differ (an admin approving from an address they have never used, a
requester on foreign infrastructure), because one person played every role;
and it cannot express application-reputation discriminators, because both
chains use Microsoft's own first-party application and that metadata is not
in the logs collected. So the two incidents were, and remain, the same
observation.

**Why threshold tuning cannot solve it.** Any change to `score_bonus`, to a
signal weight or to a severity band moves both incidents together, because
they are the same input. A threshold that suppresses the twin suppresses the
attack by the same amount; one that keeps the attack keeps the twin. The
score is a function of the evidence, and the evidence carries no intent. So
the rule was **not** tuned: `score_bonus` is still 10, the sequence, window,
actor binding and entity link are byte-for-byte unchanged (pinned by a test),
and the twin still fires.

**Why the rule is being reclassified.** `IDT-CORR-006` is correct about what
it observes - "a blocked user's risky-scope request was approved by an admin
and the user then signed in" - and wrong to be read as "an attacker did this".
It is now a `workflow_review` rule: *High-risk OAuth admin-consent workflow -
analyst review required*. It does not claim compromise. Its severity is
capped at `high` unless independent evidence exists (below). The change is in
what the incident *means* and how it is *scored*, not in what it matches.

**Detection is separated from escalation.**

| | Base detection (always) | Escalation to critical (only with independent evidence) |
|---|---|---|
| What | the 3-step chain (`IDT-CORR-006`) | a `new_country` or `new_device` baseline deviation on one of the chain's own events |
| Effect | incident at `workflow_review`, severity capped at `high` | the deviation's weight is added to `behavioral_deviation`, the cap is lifted, severity follows the score |
| Recorded | `classification`, `escalation.cap_applied`, `score_breakdown.uncapped_score` | `escalation.escalated`, `escalation.evidence` (event, actor, type, weight, reason) |

Evidence that is *not* accepted, with the reason: `new_ip` (the lab itself
showed ordinary ISP address drift on identical activity), `new_app` (a
blocked-then-approved application is new to the requester by construction, so
it is implied by the workflow rather than independent of it) and
`unusual_login_hour` (weak). The escalation types are validated against the
deviation layer's actual output (`DEVIATION_TYPES`), so a rule cannot cite a
signal we do not produce.

**What would be required to escalate to critical - and what exists today.**
Escalation evidence the deviation layer can already produce is implemented
(`new_country`, `new_device` on the requester's sign-in events; audit events
carry neither field, so admin-side country/device deviation cannot be
evaluated - only IP, which is excluded above). It has **never fired on real
data**: every real identity has a single-session history, so no chain has
had a baseline to deviate from. It is covered by synthetic-shaped integration
tests, not by real observation, and that is stated here rather than implied.
The rest of the list is documented as *required but not implemented*, because
we have no telemetry for it:

| Escalation evidence | Status |
|---|---|
| Requester behavioral deviation (`new_country`, `new_device`) | implemented; never observed on real data (no multi-day baseline) |
| Admin behavioral deviation | not evaluable: audit logs carry no country/device; `new_ip` excluded |
| Unusual/new application or service principal | not implemented - needs directory metadata (app age, ownership) we deliberately do not collect |
| Publisher verification risk | not implemented - same: directory metadata |
| New geography/device beyond baseline deviations | covered by the two rows above |
| Downstream sensitive-resource access after the success | not implemented - not observable in the tested tenant (no Exchange/SharePoint workload) |
| Additional privilege or persistence activity (role assignment, new credentials, mailbox rule) | not implemented as an escalation input; its atomic detections exist but are not wired into this rule |

**Why cumulative permission lists distort scoring.** `DelegatedPermissionGrant.Scope`
holds the *cumulative* scope of the grant: `newValue` repeats everything
already granted. Scoring it means every future grant re-fires on permissions
granted in earlier, unrelated events. On the real data that inflated both
chains: `IDT-ENTRA-002` (`offline_access`, weight 45 - the heaviest signal,
and the one the chain selects) fired on an `offline_access` granted long
before, and the twin's own prior scope already contained `Mail.Read` and
`Files.Read.All` left by the *attack* chain. The extractor now scores only
`newValue` minus `oldValue` (absent or unparseable `oldValue` = the whole
grant is new; the cumulative value stays in `raw_event_ref`). This is a
correction to what an event *added*, applied to every grant event, not a
change tuned to either chain - and it does not remove the twin.

**Scoring, before and after** (real data, both chains re-ingested fresh):

| | Attack (user3, `Mail.Read`) | Twin (user1, `Mail.ReadWrite`) |
|---|---|---|
| Scope added by the grant (delta) | `Mail.Read` | `Mail.ReadWrite` |
| Risky-scope signal before -> after | `IDT-ENTRA-002` (45, from prior `offline_access`) -> `IDT-ENTRA-001` (35) | same |
| Event risk | 75 -> 65 | 75 -> 65 |
| Behavioral deviation | 0 -> 0 | 0 -> 0 |
| Chain bonus | 10 -> 10 (untouched) | 10 -> 10 |
| **Score / severity** | **85 critical -> 75 high** | **85 critical -> 75 high** |
| Confidence | 0.85 -> 0.85 | 0.81 -> 0.81 |
| Classification | `attack_chain` (implicit) -> `workflow_review` | same |

Both still identical to each other - which is the point. Two separable
effects, so neither is credited with the other's work: the delta fix removes
the 10-point inflation (85 -> 75); the reclassification changes the meaning
and adds the cap, which on these two chains did not bind (75 < 84). The cap
binds when chain signals alone reach 85, e.g. a grant that genuinely *adds*
`offline_access` plus a risky scope (45+15+15+10): capped at 84/high, with
`uncapped_score` recorded (tested). Removing the inflation also changed the
isolated rules on real data, as a side effect and not as a goal: 8
`IDT-ENTRA-002` matches disappeared (4 of them on benign events), so isolated
false-positive alerts went 21 -> 17 (precision 0.580 -> 0.595, FPR 0.106 ->
0.086) with recall unchanged at 1.0 and no match added. Those 8 include the
paired `Remove delegated permission grant` records Entra writes alongside
each `Add` (same old/new values as the Add); at this point they were still
scored as consent events - investigated and changed next, see
"`Remove delegated permission grant`: an update artifact, not a revocation".

**Metrics under both semantics.** Original result, preserved: measured as an
attack detector, the twin is a false-positive incident, and correlation
precision fell from 1.000 to **0.500** the moment it was collected. That
number is not withdrawn; it is the evidence that this rule cannot infer
intent. It is unchanged by the redesign (incidents still 2, one benign).
Reproduce both views with `scripts/report_workflow_semantics.py`.

| Semantics | Twin counts as | Result on the 2 real chains |
|---|---|---|
| **A. Attack detector** (original) | false-positive incident | 1 TP / 1 FP - precision **0.500** |
| **B. Risky-workflow detector** | correct workflow detection | 2 of 2 incidents confirmed from the raw vendor fields (block `90094` -> add-grant -> success, same user) - precision 1.000; malicious intent **unresolved** without analyst/context escalation; 0 incidents carry independent escalation evidence |

Read B carefully: it is a statement about *workflow* detection, and its
ground truth is the collection log plus the raw records - two chains, both
collected on purpose, so it demonstrates the semantics rather than estimating
a rate. Recall is not reported for B: there is no independent enumeration of
workflow occurrences to count misses against. Nothing here makes the rule
better at finding attacks; it makes the claim the rule makes honest.

**Not done, on purpose.** No `score_bonus` change; no suppression or
downgrade of the twin's incident (it remains visible, `open`, for a
reviewer); no escalation signals for telemetry we lack; no new synthetic
scenarios; the frozen holdout, seed-42 synthetic and all five multi-seed runs
were re-run and are identical to the previous snapshot (holdout correlation
recall 0.857, A2 covered), because the grant-delta change touches only the
real `DelegatedPermissionGrant.Scope` path, which synthetic and holdout
events (`ConsentAction.Permissions` arrays) do not use.

**Limits.** One twin, one tenant, one application, one person in every role.
The escalation path is implemented but unobserved on real data; whether
`new_country`/`new_device` would separate real intent needs a multi-day
baseline and a genuinely different second party - the next collection to
make, not something this change proves.

### `Remove delegated permission grant`: an update artifact, not a revocation

Raised by the delegated-scope work above, which left these events scored as a
second consent. Investigated on every real export before any change; the
correlation logic was not touched.

**What the raw records show.** Nine unique grant audit events across all real
exports: five `Add delegated permission grant` and four `Remove delegated
permission grant`. Each Remove pairs with one Add, and the pair differs in
exactly three top-level fields:

| | Add | Remove |
|---|---|---|
| `activityDisplayName` | Add delegated permission grant | Remove delegated permission grant |
| `operationType` | `Assign` | `Unassign` |
| `activityDateTime` | t | t + 1.0 ms (three pairs), t + 4.3 ms (one) |

Everything else is identical in all four pairs: `correlationId`, the actor
(`idt-admin`) and IP, both `targetResources` (Microsoft Graph and the client
service principal), and every `modifiedProperties` entry including
`DelegatedPermissionGrant.Scope` `oldValue` and `newValue`. Each also shares
its `correlationId` with a `Consent to application` event, i.e. they belong to
one consent transaction.

**The premise needs one correction.** Within a Remove, `oldValue` and
`newValue` are **not** equal: in all four the scope *grows* (for example
`...Mail.Read` -> `...Mail.Read Mail.ReadWrite`). What is identical is the
Remove's values compared with its own Add's. An `oldValue == newValue` filter
would therefore match none of the real events, and was not used.

**Classification.** Part of an update/replace sequence, recorded as a
bookkeeping pair - not a revocation:

- 4 of 4 Removes are paired with an Add on the same `correlationId` inside
  4.3 ms; none stands alone.
- The Remove appears exactly when the grant already existed: the four updates
  (`oldValue` non-empty) each have one; the single initial grant
  (`oldValue` empty, 2026-09-11) has none. Consistent with "update = Assign
  the new state + Unassign the old grant object", not with a user or admin
  removing access.
- 0 of 4 reduce the scope. No real export contains a Remove whose scope
  shrinks, so what a true revocation looks like in this tenant's logs is
  **unobserved**. This is an inference from four pairs in one tenant, not
  from Microsoft's documentation, and is stated as such.

**Decision.** A Remove/Unassign record cannot grant permissions, so the
extractor now gives it none: `permissions` is `[]`. The event is still stored
and still normalized as `oauth_consent` (action and raw evidence intact), so
nothing is dropped from the timeline. Chosen over the alternatives because it
is correct under every reading of the unresolved question: if the Remove is an
artifact, the Add already carries the grant; if a Remove were ever a true
revocation, it must not be scored as a grant either. No revocation event type
was added: with zero observed reductions there is nothing to model against.
Left unchanged, one consent action was scored twice (two `IDT-ENTRA-001`
alerts 1 ms apart, and duplicate privilege evidence).

**Known trade-off.** If only the Remove of a pair were ever exported - an
export boundary falling inside the ~1-4 ms gap - the grant would go unscored.
Tested and documented, not mitigated: it needs the gap to straddle a window
edge, and the correlation chain already selects the earlier (Add) event.

**Effect** (real data re-ingested fresh; 227 events, unchanged):

| | Before | After |
|---|---|---|
| Atomic alerts | 42 | **39** (-3: `IDT-ENTRA-001` on the Removes of the `Files.Read.All`, `Mail.Read` and twin `Mail.ReadWrite` grants; none added) |
| Baseline deviations | - | identical |
| Correlation matches / incidents | 2 | 2, byte-identical (same ids, evidence, scores 75 / high, confidence) |
| Correlation precision / recall | 0.500 / 0.286 | unchanged |
| Workflow view (A: 1 TP, 1 FP, 0.500; B: 2/2, 1.000) | | unchanged (`report_workflow_semantics.py` output identical) |
| Isolated precision | 0.595 (25 TP / 42) | **0.590** (23 TP / 39) |
| Isolated FPR | 0.086 (17 FP / 198) | 0.081 (16 FP / 198) |
| Isolated recall | 1.000 | 1.000 |
| Alert-reduction ratio | 21.0 | 19.5 (still degenerate: 2 incidents over 39 alerts) |

The isolated precision went *down*: two of the three removed alerts were on
events labelled malicious (they counted as true positives) and one on the
benign twin's. The change was made for event-model correctness, not for a
better number, and the number did not improve. Seed-42 synthetic, all five
multi-seed runs and the frozen holdout are identical (0 differences; holdout
correlation recall 0.857) - none of them use the Remove shape.

**Limits.** Four pairs, one tenant, one actor. Whether a genuine revocation
appears as a Remove with a shrinking scope, or as something else, is
untested; it would need a deliberate revoke in the lab tenant.
*(Since resolved - see "Real revocation experiment: how Entra logs a genuine
permission reduction" below: it is the same Add + Remove pair.)*

### Real revocation experiment: how Entra logs a genuine permission reduction

Closes the question the previous section left open ("0 of 4 Removes reduce
the scope; a true revocation is unobserved"). One targeted experiment in the
lab tenant, run before any detection change: `Mail.ReadWrite` was removed
from the existing admin-consented grant (`consentType AllPrincipals`, client
`54a000cd...`) with `PATCH /oauth2PermissionGrants/{id}`, then the temporary
helper scope the call needed (`DelegatedPermissionGrant.ReadWrite.All`) was
removed again. The audit log was exported unchanged
(`real_data/entra_revocation_*`) and ingested as `real_benign`.

**Result: a genuine reduction is logged exactly like an update - an Add +
Remove pair.** Not a standalone Remove, not a different event type.

| Operation (UTC) | Events | old scope -> new scope |
|---|---|---|
| 17:45:15 helper consent (growth) | Add + Remove + `Consent to application` | 12 -> 13 (`+DelegatedPermissionGrant.ReadWrite.All`) |
| **17:46:19 revoke `Mail.ReadWrite`** | **Add + Remove** | **13 -> 12 (`-Mail.ReadWrite`)** |
| **17:46:20 drop helper scope** | **Add + Remove** | **12 -> 11 (`-DelegatedPermissionGrant.ReadWrite.All`)** |
| 17:45:19 (see below) | Add + Remove | 12 -> 11 (`-Mail.ReadWrite`) |

Compared field by field across all four pairs (and the four update pairs from
the previous section), a reduction pair is structurally indistinguishable
from a growth pair:

- Within each pair: same `correlationId`, actor, IP, `targetResources` and
  every `modifiedProperties` value; they differ only in `activityDisplayName`,
  `operationType` (`Assign`/`Unassign`) and a timestamp 1-2 ms apart.
- Both events of a reduction pair carry `oldValue` ⊃ `newValue`. **The event
  named `Add delegated permission grant` is the one that removed the scope.**
  The name and `operationType` describe the bookkeeping, not the direction.
- The only reliable signal of direction is the scope sets themselves
  (`new - old` non-empty = growth, `old - new` non-empty = reduction). Cosmetic
  difference seen: the reduced value lost its leading space.
- A `Consent to application` event accompanied the consent (growth) only, not
  the reductions.

**Is `permissions=[]` for Remove/Unassign still correct? Yes - kept.** It is
correct for every event in the experiment: the Remove halves of both
reductions and of the growth. It was also necessary to look at the *Add*
half, which is where a naive model would go wrong: it says "Add", but
removed a scope. It is already handled, by the scope-delta extraction from
the earlier redesign (`newValue` minus `oldValue` = empty for a reduction),
not by the Remove rule.

The measured value of that: scored on the *cumulative* `newValue` (the model
before the delta fix), this one revocation would have raised **16 consent
alerts** (`IDT-ENTRA-001` and `-002` on all 8 grant events, because
`Files.Read.All`, `Mail.Read` and `offline_access` all remain in the grant).
Current code raises **0**. So the delta rule, not just the Remove rule, is
what makes a revocation safe.

**No distinct normalized event type is required, so none was added.** Nothing
consumes a "revocation" today, no detection is wrong without one, and adding
a schema field would expand scope. If a future rule ever needs revocation as
a signal, the smallest change would be to derive it from `old - new` in the
extractor; that is noted, not built. The change made is regression tests only
(6 new, in `tests/integration/test_grant_remove_semantics.py`: the reduction
shape equals the update shape; neither half carries permissions; no alert
although risky scopes remain; a never-risky scope drop is silent; a
revocation cannot complete the `IDT-CORR-006` chain).

**A second finding, unplanned: an audit event for a write that did not
persist.** The first `revoke-scope` attempt returned `400 Permission being
updated or deleted is not found` at 17:45:19 - seconds after the helper
consent had replaced the grant. Nonetheless the audit log holds an Add +
Remove pair at 17:45:19.43 recording `Mail.ReadWrite` removed (12 -> 11), from
the script's IP. The change did **not** persist: the successful revoke at
17:46:19 shows `old` still containing `Mail.ReadWrite` (13 scopes). So the
directory audit log recorded an attempted reduction the API had rejected -
plausibly a replication race the experiment itself triggered. One instance,
one tenant; the cause is not established. What it does show is that a single
audit record is not proof that the grant changed, which matters for any claim
built on audit events alone (the pair pattern above is unaffected).

**Effect of ingesting the experiment** (11 real events: 9 audit + 2 sign-in;
the current code was used unchanged):

| | Before | After |
|---|---|---|
| Benign events | 198 | 209 |
| Atomic alerts | 39 | 40 (+1: `IDT-ENTRA-003` on the admin's own device-code sign-in, which the experiment required; benign) |
| Alerts from the 8 grant events | - | 0 |
| Incidents / correlation matches | 2 | 2, unchanged (75 / high) |
| Correlation precision / recall | 0.500 / 0.286 | unchanged |
| Workflow view A / B | 0.500 / 1.000 | unchanged |
| Isolated precision | 0.590 | 0.575 (the one added benign alert) |
| Isolated FPR | 0.081 | 0.081 (17 FP / 209) |
| Correlation FPR | 0.200 (1 / 5 benign files) | 0.143 (1 / 7): a denominator effect, not an improvement |
| Alert-reduction ratio | 19.5 | 20.0 (still degenerate) |

Seed-42 synthetic, all five multi-seed runs and the frozen holdout are
identical (0 differences; holdout correlation recall 0.857). Nothing in
detection or correlation logic was changed by this experiment.

**Limits.** One reduction, one grant, one tenant, one actor; the tenant is
a lab. Whether other revocation paths (deleting the whole grant, revoking
from the portal, per-user `Principal` grants) log the same pair is untested
and was deliberately not pursued.

## API & dashboard

- `POST /api/evaluation/run` - single-run synthetic evaluation.
- `/evaluation` (dashboard) - same, rendered, with a re-run form.
- `python -m app.evaluation.harness` functions `run_multi_seed_evaluation()`
  and `app.evaluation.holdout_runner.run_holdout_evaluation()` - not yet
  wired to their own dashboard pages/endpoints (a reasonable next
  addition; the single-run page and direct Python/script invocation cover
  today's need).
- `GET /api/alerts`, `/alerts` (dashboard) - high/critical atomic matches
  as their own queue, complementary to `/incidents` (Phase 9 #9).

## Testing

- `tests/unit/test_evaluation_scenarios.py` - generators, determinism,
  the six noisy personas, the four ambiguous singletons, scale (id
  uniqueness at 90 attack scenarios).
- `tests/unit/test_evaluation_metrics.py` - `compute_metrics()` against
  hand-built fixtures, including F1 and sequence-based FPR.
- `tests/integration/test_evaluation_harness.py` - end-to-end claims:
  perfect isolated recall by construction, A1-A5 fully correlated vs.
  A6's gap, zero false-positive incidents, F1 correlation > F1 isolated
  under realistic noise, multi-seed determinism and aggregation.
- `tests/unit/test_holdout.py`, `tests/integration/test_holdout_runner.py` -
  the holdout generator and the frozen file itself.
- `tests/integration/test_ingest_real_export.py`,
  `test_report_by_provenance.py` - the real-data path, tested against
  this project's own real-schema fixtures standing in for a genuine
  export.
