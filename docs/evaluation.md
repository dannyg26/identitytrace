# Evaluation Harness (Phase 7)

Answers the project's primary research question (§2.1): **can cross-domain
identity correlation detect account-takeover attack chains with better
precision and lower analyst alert volume than isolated authentication
rules?** - with a reproducible, labeled dataset run through the real
pipeline, not an assertion.

## Design

- **Fixed seed, reproducible.** `run_evaluation(seed=42, ...)` always
  produces the same dataset and the same metrics -
  `tests/integration/test_evaluation_harness.py::test_evaluation_is_deterministic_given_the_same_seed`
  checks this directly.
- **Runs the real pipeline.** Every generated event goes through
  `app.pipeline.process_event()` - the identical code the live API calls.
  Nothing about detection, baselining, or correlation is reimplemented for
  evaluation purposes, so there's no risk of the harness and the app
  quietly drifting apart.
- **Never touches live data.** Each run creates a fresh in-memory SQLite
  database, uses it, and discards it. Hitting `POST /api/evaluation/run`
  or `/evaluation` on a running instance cannot pollute real SOC data with
  synthetic incidents - verified in
  `tests/integration/test_event_pipeline.py::test_evaluation_api_and_dashboard`.
- **Ground truth lives outside the pipeline.** A `GeneratedEvent`'s
  `label`/`attack_id`/`attack_type` never appear inside the payload the
  pipeline sees (blueprint §10.1.3) - they're tracked only in the
  generator's own return value, compared against the pipeline's output
  after the fact.
- **Three-layer dataset**, scaled to this project rather than to BOTS-size
  background noise (§10.1.2): a benign population (routine daily logins
  for several identities), benign edge cases deliberately designed to
  *look* suspicious without being malicious, and labeled attack instances
  for all six scenarios - each with its own short benign baseline history
  before the attack, so Phase 3 deviations have something real to deviate
  from.

## The comparison that matters

For every attack scenario instance, two independent questions get asked:

1. **Isolated-rule baseline**: did *any* Phase 2 atomic detection match
   fire on one of the scenario's malicious events?
2. **Correlation engine**: did a Phase 4 incident form that includes one
   of those events as evidence?

This directly operationalizes §10.2's baseline comparison. "Alerts" for
the isolated baseline are individual `DetectionMatchRecord` rows (what an
analyst would see with no correlation at all); for the correlation engine
they're `IncidentRecord` rows.

## A representative result (seed 42, 2 instances per scenario)

```
                    recall   precision   false positives      avg latency
isolated rules       1.00      1.00      0 alerts (FPR 0.0)      120s
correlation engine   0.83      1.00      0 incidents             486s

alert reduction: 30 atomic alerts -> 10 incidents (3.0x)
```

Read honestly, not favorably:

- **Isolated rules detect faster** (0s latency on most scenarios - the
  very first malicious event trips a rule immediately) **but tell a
  thinner story**: one alert, no context, no chain.
- **Correlation is slower by construction** - it can only report once the
  *whole* required sequence has happened - but turns 3 raw alerts into 1
  incident on average here, with zero false positives on deliberately
  tricky benign data (a traveling employee's new device+country, a data
  analyst's routine large exports).
- **Correlation's recall gap is real and documented, not hidden**: A6
  (SaaS data theft) is generated as a standalone bulk-transfer signal with
  no preceding chain, and no correlation rule matches on a single signal
  by design (`app/correlation/schema.py` requires 2+ steps). Isolated
  rules catch it every time; the correlation engine, honestly, never
  forms an incident for it alone. That's the price of this project's
  5-rule correlation library, not a bug - see
  [`correlation.md`](correlation.md) for why IDT-CORR-002 through 005 all
  require a *second* signal type, and consider a dedicated A6 correlation
  rule (e.g. `new_session_context -> bulk_data_access`) a natural next
  addition if this gap matters for a given deployment.

Numbers will vary slightly with `scenarios_per_type` and `seed` - run
`/evaluation?seed=<n>&scenarios_per_type=<n>` or `POST /api/evaluation/run`
to reproduce or explore.

## What this does and doesn't prove

**Does**: shows, on a labeled dataset this project fully controls, that
chaining Phase 2+3 signals through Phase 4 correlation reduces alert
volume without losing precision, at the cost of recall on
single-signal-only attacks and detection speed. That's a real, measured
trade-off - not an assertion.

**Doesn't**: generalize beyond this lab dataset (blueprint's explicit
non-goal, §3.2). The attack generators produce exactly the signal
sequences this project's own detections and correlation rules were built
to recognize - a fair test of whether the *architecture* works, not of
real-world detection performance against telemetry the rules were never
designed with in mind. No BOTS v2/v3 background telemetry is mixed in
(§10.1.1's "Layer 1") - the benign population here is synthetic routine
logins, not the ambient noise of a real enterprise. Both are documented
gaps a portfolio reviewer should be able to see immediately, not have to
discover.

**A narrower, complementary check that *was* done**: rather than BOTS
(which turned out to require an actual running Splunk instance - no
plain-file export exists), every normalizer was validated against
fixtures shaped like each source's real, officially-published API schema,
not this project's own invented shapes. That check found and fixed four
real bugs, including one that would have crashed on a genuine Entra audit
payload. It doesn't change any number on this page (a schema-fidelity
check, not a new detection dataset), but it's real evidence the parsers
would survive contact with an actual tenant's export. See
[`normalizer-fidelity.md`](normalizer-fidelity.md).

## Methodology notes

- "Isolated-rule" false positives/precision count only Phase 2
  `DetectionMatchRecord`s - Phase 3 baseline deviations aren't "rules" in
  the blueprint's L1 sense (§7), so they're excluded from that specific
  comparison (the traveling-employee edge case *does* produce deviations;
  it correctly produces zero atomic-rule alerts and zero incidents).
- Detection latency is measured from a scenario's first malicious event's
  timestamp to the earliest qualifying alert/incident timestamp - not
  wall-clock ingestion time (everything runs through the pipeline
  sequentially in one process either way).
- A false-positive incident is one whose evidence contains no malicious
  event at all. An incident with a mix of malicious and benign evidence
  counts as a true positive - it correctly caught the attack, additional
  benign context notwithstanding.

## API & dashboard

- `POST /api/evaluation/run` - body: `{seed, scenarios_per_type,
  num_benign_identities}`, all optional (defaults: 42, 2, 5). Returns the
  full metrics object.
- `/evaluation` (dashboard, blueprint §9.1's "Evaluation" page) - same
  thing rendered, with a form to re-run at a different seed/scale.

## Testing

- `tests/unit/test_evaluation_scenarios.py` - every generator produces
  correctly-labeled, uniquely-identified events; ground truth never leaks
  into a payload; generation is deterministic.
- `tests/unit/test_evaluation_metrics.py` - `compute_metrics()` against
  hand-built fixtures: recall/precision/FPR/latency/alert-reduction math,
  isolated-vs-correlated independence, scenario-type grouping.
- `tests/integration/test_evaluation_harness.py` - the real end-to-end
  claims: perfect isolated recall by construction, A1-A5 fully correlated
  while A6 isn't (the documented gap), zero false-positive incidents from
  the benign edge cases, and alert reduction > 1.
- `tests/integration/test_event_pipeline.py::test_evaluation_api_and_dashboard` -
  the API and dashboard, and the "never touches live data" guarantee.
