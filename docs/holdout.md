# Frozen Holdout Dataset (Phase 9 #6)

## Why

The detector's rules/correlation logic and the main synthetic generator
(`app/evaluation/scenarios.py`) were developed together - same author,
same sitting, each informed by watching the other's output. That's a real
risk of circular evaluation: the generator could unconsciously produce
exactly what the detector expects. A held-out, differently-parameterized
set is the check.

## What's in it

`tests/fixtures/holdout/holdout_v1.json`, generated once by
`scripts/freeze_holdout.py` (seed 999, base date 2027-01-05 - deliberately
not the main generator's seed 42 / 2026-09-01) and checked into git:

- The same six attack families (A1-A6) and the main benign personas, at
  different timing/volumes/identities than the main set - not a byte
  copy, but not claiming to be unrelated either.
- **`shared_workstation`**: a benign persona not in the main generator -
  three different identities briefly using the same `device_id`, testing
  that per-identity baselines don't cross-contaminate just because a
  device repeats across actors.
- **`COMBO`**: an attack combination none of the five original correlation rules
  were specifically written around - a new-device/new-country signin,
  followed by a role assignment, followed by sensitive access. Every
  individual signal exists in the main generator; this exact sequence
  doesn't.

## Freeze discipline

`scripts/freeze_holdout.py` refuses to overwrite an existing frozen file.
**The holdout data itself is never edited to improve a score.** If the
detector needs to change in response to a holdout failure, the change
goes into `app/detections/`, `app/baselines/`, or `app/correlation/` -
never into `tests/fixtures/holdout/holdout_v1.json`. A new holdout
generation (`holdout_v2.json`, a new `freeze_holdout.py` run) is only for
extending coverage, never for making an old failure disappear.

## Result log

### holdout_v1, first run (2026-09-10)

```
Totals:    21 attack scenarios, 106 benign events (17 sequences), 48 malicious events
           73 atomic alerts, 18 incidents

Isolated rules:      recall 1.00  precision 0.712  f1 0.832  FPR 0.198  latency 154s
Correlation engine:  recall 0.857 precision 1.00   f1 0.923  FPR 0.0    latency 570s
Alert reduction:     4.06x

COMBO (novel combination, never in the main generator):
  isolated recall 1.00, correlated recall 1.00

A6 (no correlation rule, by design):
  isolated recall 1.00, correlated recall 0.0  -  consistent with the main dataset
```

**Observed failures**: none. Every prediction the holdout set's design
was meant to test held: isolated recall stayed perfect, correlation
stayed at zero false positives on genuinely unseen benign variety
(including the new `shared_workstation` persona), A6's designed gap
reproduced exactly, and the novel `COMBO` attack - a combination that was
never in the main generator - was caught by *both* layers. This is a
positive, non-trivial result: `IDT-CORR-003`'s sequence-matching logic
generalized to a chain shape it wasn't written for, rather than only
working on the exact five patterns it was tuned against.

**Engineering changes made in response**: none - there was nothing to
respond to. This log entry exists regardless, per the anti-overfitting
discipline: a clean first run is itself the record, not a reason to skip
recording it.

### holdout_v1, run after the `IDT-ENTRA-003` v2 revision (2026-09-21, measured late)

This run should have happened when `IDT-ENTRA-003` was revised (2026-09);
it was checked against the real corpus and the test suite but not the
holdout, and was only measured when a later change needed a baseline.

```
Totals:    21 attack scenarios, 106 benign events (17 sequences), 48 malicious events
           70 atomic alerts, 15 incidents            (was 73 alerts, 18 incidents)

Isolated rules:      recall 1.00  precision 0.700  f1 0.824  FPR 0.198  latency 211s
Correlation engine:  recall 0.714 precision 1.00   f1 0.833  FPR 0.0    latency 560s
Alert reduction:     4.67x                          (was 4.06x)

A2:  isolated recall 1.00, correlated recall 0.0    (was 1.0 - all 3 instances)
Every other family (A1, A3, A4, A5, COMBO): unchanged; A6 gap unchanged.
```

**Observed failure**: `IDT-CORR-001` no longer completes for any of the 3
frozen A2 instances. Correlation recall 0.857 -> 0.714.

**Cause (verified, not inferred)**: the frozen holdout contains exactly 3
payloads carrying the legacy `authenticationProtocol: "deviceCode"` (one
per A2 instance) and 0 carrying the real `clientAppUsed` shape.
`IDT-ENTRA-003` v2 matches only the derived `nativeClient` value, so the
holdout's device-code sign-ins no longer emit `new_session_context`.
Letting the rule also accept `deviceCode` - patched in memory only,
nothing changed on disk - returns the holdout *exactly* to its documented
result (recall 0.857, 18 incidents, 73 alerts, A2 1.0, 0 false-positive
incidents).

**Engineering change made in response**: none yet. The holdout data is not
edited (freeze discipline). The detector-side change this points at is
small and independently justified - v2 should not have stopped honoring a
documented Graph value (`deviceCode`) for a tenant that does populate it,
since that is strictly stronger evidence than the `nativeClient` fallback
- but it is a change to a detection rule and is left as an explicit
decision rather than bundled into an unrelated task.

### holdout_v1, run after adding `IDT-CORR-006` (2026-09-21)

A strict programmatic diff of the entire result (holdout, the seed-42
single run, and all 5 seeds of the multi-seed run, including per-scenario
detail) against the same measurements taken immediately before the change:
**0 differing values.** Expected, not merely observed - no holdout or
synthetic event carries a 90094 sign-in or a service-principal entity, so
the new rule has nothing to fire on. The 0.714 above is therefore carried
through unchanged, not introduced or repaired here.

### holdout_v1, run after the `IDT-ENTRA-003` v3 compatibility restoration (2026-09-21)

**This is a compatibility restoration, not a detection improvement.** The
regression logged two entries above was caused by v2's telemetry-model
change, which made the rule match only the derived `nativeClient` value and
so stopped honoring the documented `authenticationProtocol == "deviceCode"`
that the frozen holdout still carries. v3 accepts exactly those two
equivalent representations (`nativeClient`, `deviceCode`) and nothing else.
No holdout data was edited.

```
Totals:    21 attack scenarios, 106 benign events (17 sequences), 48 malicious events
           73 atomic alerts, 18 incidents

Isolated rules:      recall 1.00  precision 0.712  f1 0.832  FPR 0.198  latency 154s
Correlation engine:  recall 0.857 precision 1.00   f1 0.923  FPR 0.0    latency 570s
Alert reduction:     4.06x

A2:  isolated recall 1.00, correlated recall 1.00   (restored; was 0.0)
```

**Observed failure**: none remaining. All 17 figures in the first-run entry
(totals, isolated and correlation recall/precision/F1/FPR/latency, alert
reduction) match exactly, and only the three A2 scenarios changed relative
to the post-v2 run. Correlation recall 0.714 -> 0.857.

**Engineering change**: `IDT-ENTRA-003` v2 -> v3 (`auth_protocol in
[nativeClient, deviceCode]`). The change was applied only after the cause
was verified with an in-memory-only patch that produced the identical
result, and it is regression-tested at the rule boundary (both values
match; `interactive`, `basic`, `ropc`, case variants, empty and absent
values do not; a failed sign-in still does not).

**Lesson recorded**: a rule change that alters how an event type is
recognised must re-run the frozen holdout, not only the real corpus and
the unit suite - the holdout is the only place the *old* telemetry shape
still lives.

### holdout_v1, run after the grant-delta scoring fix and IDT-CORR-006 reclassification (2026-09-21)

**Change**: `DelegatedPermissionGrant.Scope` extraction now scores only the
scopes a grant *added* (`newValue` minus `oldValue`), and `IDT-CORR-006`
became a `workflow_review` rule with a severity cap. Both alter how consent
events are recognised/scored, so the holdout was re-run, as the v3 lesson
requires.

**Result**: identical to the previous snapshot in every reported figure -
correlation recall 0.857, precision 1.0, A2 covered (3/3 instances), A6
correlated recall 0.0 as before; seed-42 synthetic and all five multi-seed
runs also identical (0 differences in a full structural diff).

**Why nothing moved**: the holdout's consent events carry
`ConsentAction.Permissions` arrays, not the `DelegatedPermissionGrant.Scope`
path the fix changed, and none of its chains involve `IDT-CORR-006`.

### holdout_v1, run after `Remove delegated permission grant` events stopped carrying permissions (2026-09-21)

**Change**: an Entra `Remove delegated permission grant` audit event (the
bookkeeping half of an update = Add + Remove pair) no longer contributes
granted permissions. It alters how consent events are scored, so the holdout
was re-run.

**Result**: identical - correlation recall 0.857, precision 1.0, A2 covered;
seed-42 synthetic and all five multi-seed runs also identical (0 structural
differences). The holdout's consent events are `ConsentAction.Permissions`
arrays and contain no Remove-grant events.

### holdout_v1, run after the real revocation experiment (2026-09-21)

**Change**: none to detection or normalization. One real revocation was
performed and its audit events ingested; regression tests were added. The
holdout was re-run to confirm nothing moved.

**Result**: identical - correlation recall 0.857, precision 1.0, A2 covered;
seed-42 synthetic and all five multi-seed runs also identical (0 structural
differences).

*(Future holdout runs - after any detector change - get their own dated
entry above this line: original result, observed failure if any,
engineering change, new result. Never overwrite this entry.)*

## Reproducing

```bash
python -c "from app.evaluation.holdout_runner import run_holdout_evaluation; \
    import json; print(json.dumps(run_holdout_evaluation(), indent=2))"
```

or via the test suite: `pytest tests/integration/test_holdout_runner.py -v`.
