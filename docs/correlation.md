# Temporal Correlation & Incidents (Phase 4)

This is the blueprint's MVP cut line (§11.1): normalized telemetry, tested
atomic detections, baselines, and now correlated incidents. Everything
after this phase improves breadth, visualization, and research rigor -
it doesn't change what a "detection" fundamentally is.

## The core idea

A single signal - one detection match, one baseline deviation - is weak
evidence on its own (the project's thesis, §1). Phase 4 chains related
signals for the *same identity*, in a *time window*, in a *specific order*,
into one incident with an explainable score and confidence.

## Signal vocabulary

Correlation rules are written against abstract "signals," not literal rule
IDs - matching the blueprint's own §16.2 example (`new_session_context`,
`risky_oauth_consent`, `sensitive_resource_access`, ...). Two sources feed
this vocabulary:

- **Detection rules** (Phase 2) carry an optional `signal:` tag in their
  YAML; several rules can share one signal (e.g. both OAuth-consent rules
  feed `risky_oauth_consent`). Defaults to the rule's own id if untagged.
- **Baseline deviations** (Phase 3) use their `deviation_type` directly as
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
Phase 2 rule scores themselves (e.g. `IDT-GITHUB-003`'s sensitive-repo-name
check already *is* an asset-sensitivity signal) and doesn't implement
context-based suppression yet (a Phase 8 concern) - see
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

5 rules under `correlations/`, covering every attack scenario (A1-A6, via
overlap - e.g. A6's `bulk_data_access`/`sensitive_resource_access` signals
appear as the terminal step of several chains):

| ID | Sequence | Window | Scenario |
|---|---|---|---|
| IDT-CORR-001 | new_session_context &rarr; risky_oauth_consent &rarr; sensitive_resource_access | 15m | A2 |
| IDT-CORR-002 | new_device &rarr; new_country &rarr; bulk_data_access | 30m | A1 |
| IDT-CORR-003 | privilege_escalation &rarr; sensitive_resource_access | 30m | A5 |
| IDT-CORR-004 | weak_auth_session &rarr; new_ip &rarr; bulk_data_access | 10m | A3 |
| IDT-CORR-005 | repo_access &rarr; sensitive_resource_access &rarr; bulk_data_access | 20m | A4 |

IDT-CORR-001 is the blueprint's own §16.2 reference example, adapted to
this project's signal names.

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
