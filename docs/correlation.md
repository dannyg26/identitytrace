# Temporal Correlation & Incidents

Correlation combines atomic detections and baseline deviations into incidents
with traceable evidence and explainable scores.

## The core idea

A single signal - one detection match, one baseline deviation - is weak
evidence on its own (the project's thesis, §1). Correlation chains related
signals for the *same identity*, in a *time window*, in a *specific order*,
into one incident with an explainable score and confidence.

## Signal vocabulary

Correlation rules are written against abstract "signals," not literal rule
IDs - matching the blueprint's own §16.2 example (`new_session_context`,
`risky_oauth_consent`, `sensitive_resource_access`, ...). Two sources feed
this vocabulary:

- **Detection rules** carry an optional `signal:` tag in their
  YAML; several rules can share one signal (e.g. both OAuth-consent rules
  feed `risky_oauth_consent`). Defaults to the rule's own id if untagged.
- **Baseline deviations** use their `deviation_type` directly as
  the signal name (`new_device`, `new_country`, `volume_anomaly`, ...) -
  already exactly the vocabulary correlation needs, no tagging required.

See `app/correlation/signals.py`.

## Matching: greedy earliest-occurrence subsequence

`app/correlation/engine.py`'s `find_chain()`: for each required step in a
rule's `sequence`, take the earliest signal of that type at or after the
previous step's timestamp. This is a simple, cheap, deterministic ordering
check - not a general interval-scheduling optimum - but it's exactly what
an attack-chain sequence needs: did these things happen, for this
identity, *in this order*, inside the window.

Signals sharing the exact same timestamp (e.g. three detection rules all
firing off one particularly evidence-rich event) can satisfy consecutive
steps - the comparison is `>=`, not `>`.

## Scoring & confidence (blueprint §7.2)

```
incident_score = clamp(event_risk + behavioral_deviation + temporal_chain_bonus, 0, 100)
confidence = 0.4*correlation_strength + 0.3*evidence_quality + 0.3*telemetry_completeness
```

The blueprint's formula also lists `asset_sensitivity`, `privilege_context`,
and `benign_context_adjustments`. This project folds the first two into
atomic rule scores themselves (e.g. `IDT-GITHUB-003`'s sensitive-repo-name
check already *is* an asset-sensitivity signal) and doesn't implement
general context-based suppression - see
`app/correlation/scoring.py`'s docstring for the full reasoning. Every
component is stored on the incident (`score_breakdown`,
`confidence_breakdown`) - never a black box.

`confidence` decomposes the blueprint's three named factors concretely:

| Factor | Meaning here |
|---|---|
| `correlation_strength` | How tightly the matched chain clustered in time vs. the rule's window - fast chains score higher, per the blueprint's own "minutes, not hours" thesis. |
| `evidence_quality` | `len(sequence) / 4`, capped at 1.0 - a chain requiring more independent signal types is less likely to be coincidence. |
| `telemetry_completeness` | Fraction of the chain's contributing events that carry `raw_event_ref` - can an analyst actually go inspect the source evidence. |

This is a deliberately simple, fully-explainable heuristic - not a
calibrated probability. Severity bands collapse the blueprint's 5-level
scale (§7.3) onto the 4-level `Severity` vocabulary already used everywhere
else in this project (low/medium/high/critical), merging "Suspicious"
(30-49) and "Medium" (50-69) into one `medium` band.

## Incident lifecycle

- **Creation/update is idempotent per chain occurrence.** `incident_id =
  f"{rule.id}:{first_signal.event_id}"` - deterministic, so replaying
  ingestion re-derives the same incident rather than duplicating it.
- **Analyst triage survives re-correlation.** `status`,
  `analyst_disposition`, and `notes` are set only on first creation
  (default `"open"`/`null`/`null`) and preserved on every subsequent
  update - re-detecting the same chain refreshes evidence/score but never
  silently resets what an analyst already decided. See
  `app/models/incident.py`'s `upsert_incident()`.
- **A known limitation**: the anchor is the *first* matched signal's event.
  If an even earlier qualifying signal shows up later (e.g. backfilled/
  delayed telemetry), a second incident could be created for what's really
  the same underlying chain. Acceptable at this project's scale; worth
  revisiting if out-of-order ingestion becomes common.

## Correlation rules

6 rules under `correlations/`. A6's `bulk_data_access` and
`sensitive_resource_access` signals appear in several chains, but that
signal overlap does not provide standalone A6 correlation coverage: A6
correlated recall is 0.0 in the frozen holdout. Five chain signals for a
single identity; `IDT-CORR-006` is a different kind - see
[Entity-bridged rules](#entity-bridged-rules-idt-corr-006):

| ID | Sequence | Window | Scenario |
|---|---|---|---|
| IDT-CORR-001 | new_session_context &rarr; risky_oauth_consent &rarr; sensitive_resource_access | 15m | A2 |
| IDT-CORR-002 | new_device &rarr; new_country &rarr; bulk_data_access | 30m | A1 |
| IDT-CORR-003 | privilege_escalation &rarr; sensitive_resource_access | 30m | A5 |
| IDT-CORR-004 | weak_auth_session &rarr; new_ip &rarr; bulk_data_access | 10m | A3 |
| IDT-CORR-005 | repo_access &rarr; sensitive_resource_access &rarr; bulk_data_access | 20m | A4 |
| IDT-CORR-006 | admin_consent_required (user) &rarr; risky_oauth_consent (any identity) &rarr; new_session_context (same user), all the same service principal. **Workflow review** (see below), not an attack detection | 15m | A2 |

IDT-CORR-001 is the blueprint's own §16.2 reference example, adapted to
this project's signal names.

### Entity-bridged rules (IDT-CORR-006)

Every other rule requires one `actor_id` throughout. That model cannot
express a real Entra flow: when a scope needs admin approval, the consent
is performed by an *admin*, so the chain necessarily spans two identities.
`IDT-CORR-006` models exactly the sequence validated end-to-end on real
logs (docs/evaluation.md, "A2 End-to-End Real Validation"): a user's
sign-in is blocked (`status.errorCode 90094`), an admin grants consent for
the same **service principal**, and the *same original user* then signs in
successfully. Downstream resource access is deliberately not part of it -
it was not observable in the tested tenant.

Two optional rule fields, set together or not at all (enforced when the
YAML loads):

- `actor_binding` - one entry per sequence step: `anchor` (must be the same
  actor as step 1) or `any`. The first and last steps must be `anchor`:
  bridging through another identity is only ever for the middle.
- `entity_field` - the shared entity every step must reference exactly
  (currently only `service_principal_id`, a closed set - each entity must
  be justified by real telemetry carrying it verbatim on every side).

What the matcher refuses, all tested: linking on app + time alone, a
different service principal on any step, a different user in the last
step, steps out of order or simultaneous (each must be strictly after the
previous), the whole chain not fitting inside the window, a step with no
entity (a missing entity is never a wildcard - `None` never equals `None`;
nil/placeholder GUIDs are normalized to `None`), and any failure other than
the narrow 90094 standing in for the first step.

**Ingestion-order behavior differs from the single-identity rules, on
purpose.** Those look only *backward* from the triggering event. This type
looks a full window in *both* directions, so whichever event of the chain
arrives last completes it - on real telemetry the audit and sign-in logs
come from different endpoints and audit events landed minutes before the
matching sign-ins. Re-detection is idempotent (the incident id derives from
the chain's first event). The single-identity rules' known out-of-order
limitation above is unchanged.

### Workflow-review rules (detection vs escalation)

A rule can declare `classification: workflow_review` when its chain is a
risky *workflow* that legitimate use produces identically, so the telemetry
cannot say whether it is malicious. `IDT-CORR-006` is the first: a benign
twin on the same tenant matched it with the same signals and score as the
attack (docs/evaluation.md, "A2 Benign Twin — Detection vs Intent"). Three
optional fields, validated at load:

- `classification` - `attack_chain` (default) or `workflow_review`. A
  workflow-review incident is surfaced for analyst review and never asserts
  compromise; the dashboard says so.
- `severity_cap` - required for `workflow_review`; the highest severity the
  rule may reach *without* independent evidence. The score is capped to that
  band's ceiling and the pre-cap value is kept as `score_breakdown.uncapped_score`.
- `escalation_deviations` - baseline deviation types that, when present on
  one of the chain's own events, count as independent evidence: their weights
  join `behavioral_deviation` and the cap is lifted. Only types the deviation
  layer can produce are accepted, so a rule cannot depend on telemetry we do
  not collect. `IDT-CORR-006` accepts `new_country` and `new_device`.

The match itself is unaffected - classification changes what an incident
means and how it is scored, never which chains fire. Incidents store
`classification` and an `escalation` record (cap, whether it applied,
evidence).

## API & dashboard

- `GET /api/correlation-rules` - the loaded rule library.
- `GET /api/incidents` (filter: severity/identity_id/status/scenario),
  `GET /api/incidents/{id}`, `PATCH /api/incidents/{id}` (status/
  analyst_disposition/notes).
- `GET /api/events/{id}/incidents` - which incident(s), if any, an event is
  evidence for.
- Dashboard: `/incidents` (queue), `/incidents/{id}` (detail: timeline,
  score/confidence breakdowns, ATT&CK mapping, a disposition form that
  PATCHes the API directly). Overview and identity-profile pages now show
  recent/prior incidents too.

## Testing

- `tests/unit/test_correlation_engine.py` - `find_chain()`: ordering,
  missing steps, earliest-occurrence selection, same-timestamp steps.
- `tests/unit/test_correlation_scoring.py` - severity bands, score
  clamping, confidence weighting/clamping.
- `tests/unit/test_correlation_loader.py` - YAML validation.
- `tests/integration/test_incidents.py` - the real end-to-end case: no
  incident until the full chain exists, then one incident with hand-verified
  score/confidence math, reachable from any of its evidence events,
  disposition PATCH, and disposition surviving a replay-triggered
  re-correlation.
