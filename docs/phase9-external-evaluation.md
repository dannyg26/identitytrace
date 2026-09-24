# Phase 9: External Evaluation & Real-World Validation

> Historical planning/collection reference. v1.0 collection is closed.
> Unmet expansion targets are accepted limitations or possible v1.1 work;
> this guide does not add release requirements. See the
> [final release review](release-readiness-v1.0.md).


## Phase split: 9A (done) / 9B (the only thing left)

**Phase 9A - synthetic methodology - is complete.** Noisy benign
personas, ambiguous singletons, a frozen holdout set, multi-seed
evaluation, F1/FPR, provenance tagging, the atomic-alert queue,
per-scenario analysis: all built, tested, documented. Expanding this
further (another persona, another seed count) has sharply diminishing
returns - it does not substitute for real data, and shouldn't be used as
a way to keep making progress without collecting any.

**Phase 9B - collect real vendor telemetry - is the entire remaining
roadmap**: collect → ingest unchanged
(`scripts/ingest_real_export.py`) → fix whatever the real data breaks →
run provenance-separated evaluation
(`scripts/report_by_provenance.py`) → publish the results, however they
turn out. Concrete, scaled checklist:
[`phase9b-first-collection-checklist.md`](phase9b-first-collection-checklist.md)
(target: 3-5 lab identities, 100-500 real Entra events, 100-500 real
GitHub events, several controlled suspicious sequences - not 50,000
events, a first real batch). This step requires access this coding
environment doesn't have (no Azure/Entra credentials, no `gh` CLI, no
way to complete an interactive sign-in) - it's the one piece of this
phase that has to happen outside it.

**Do not expect the real numbers to match the synthetic ones.** A result
where real precision/FPR is *worse* than the synthetic run (real logs are
messy) is a stronger, more credible finding than a second perfect score -
see `docs/evaluation.md`'s Tier 3/4 section, currently empty pending this
collection.

## Objective

IdentityTrace v1 is functionally complete and already demonstrates that the architecture works against controlled synthetic data.

The next phase should focus on making the evaluation more credible by testing the platform against:

- real vendor event schemas
- real lab-generated telemetry
- noisier benign behavior
- frozen holdout datasets
- multiple attack variants
- multiple random seeds

## Addendum: the correct division of labor (added mid-phase)

This coding environment cannot authenticate to Entra or GitHub - no
installed `gh` CLI, no Azure/Entra credentials, no way to click through a
real interactive sign-in or MFA prompt. That's a hard constraint, not a
choice. The corrected plan, adopted partway through this phase: **the
user collects real telemetry from their own lab environment and hands it
to the project as a raw export; the project consumes it unmodified.**
That's not a workaround - it's better research practice than the
alternative, because the evaluation corpus becomes a fixed external
input rather than something the detector's own author generated.

Every result from here on is labeled by exactly which of four categories
it came from - never silently blended:

- `synthetic_benign` / `synthetic_attack` - `app/evaluation/scenarios.py`,
  `app/evaluation/holdout.py`. Always available, always reproducible.
- `real_benign` / `real_controlled_attack` - real exports, tagged via
  `scripts/ingest_real_export.py --label`, reported via
  `scripts/report_by_provenance.py`. **Infrastructure built and tested;
  no real data collected yet** - see item 2/3 below and
  [`real-lab-collection-guide.md`](real-lab-collection-guide.md) for
  exactly how to produce it.

The five-tier structure this addendum introduces (unit validation / real
schema validation / live lab telemetry / mixed evaluation / optional
public background data) is documented in full in
[`evaluation.md`](evaluation.md#five-validation-tiers).

The goal is no longer to add features.

The goal is to answer:

> **Does IdentityTrace still perform well when the data is messy, realistic, and not specifically shaped around the detection logic?**

---

## Current State

IdentityTrace currently has:

- 212 passing tests
- 97% test coverage
- clean linting
- CI pipeline
- Docker support
- PostgreSQL integration
- deterministic synthetic data generation
- six attack scenario types
- atomic detections
- multi-stage correlation
- incident generation
- risk scoring
- case studies
- schema validation against real Microsoft, GitHub, and M365 payload structures

Current synthetic evaluation results:

| Metric | Isolated Rules | Correlation Engine |
|---|---:|---:|
| Recall | 100% | 83% |
| Precision | 100% | 100% |
| False Positives | 0 | 0 |
| Average Detection Latency | 120s | 486s |
| Alert Reduction | — | 3× |

The current run used:

- 12 attack scenarios
- 52 benign events
- 26 malicious events
- 78 total events
- 30 atomic alerts
- 10 correlated incidents

These results are useful for validating the architecture, but they are still entirely synthetic.

They prove:

> **IdentityTrace can correctly execute its intended detection and correlation logic on controlled data.**

They do not yet prove:

> **IdentityTrace performs reliably against realistic enterprise telemetry.**

---

# 1. Commit the Current Version

Before beginning external evaluation work, commit the current project state.

This creates a clean milestone representing:

> **IdentityTrace v1 — functionally complete, schema-validated, but not yet externally validated against real operational telemetry.**

Suggested commit message:

```text
feat: complete IdentityTrace v1 with detection, correlation, evaluation, CI, and real-schema validation
```

**Status: done.** Committed as `4308c1d` on 2026-09-10.

---

# 2. Generate Real Entra ID Lab Telemetry

The highest-value next step is to collect real identity events from a controlled Microsoft Entra lab environment.

The current Microsoft example payloads prove that the normalizers understand real API shapes.

They do not prove that the full pipeline handles real operational activity.

The goal is to generate actual events such as:

- successful authentication
- failed authentication
- new or unusual device activity
- application registration
- OAuth consent
- permission grants
- administrative role assignment
- account changes
- security-related identity changes
- user and service-account activity

The real events should be collected directly from the supported Microsoft logging/API source and passed through the normal ingestion path.

The test flow should be:

```
Real Microsoft Event
        ↓
Normalizer
        ↓
Atomic Detection
        ↓
Correlation Engine
        ↓
Incident
        ↓
Analyst Output
```

The important requirement is that the raw event should not be manually rewritten into the IdentityTrace schema before ingestion.

The normalizer must handle the original vendor structure.

**Status: infrastructure done; real data collection blocked on
credentials, not attempted as a substitute.** This environment has no
Azure/Entra tenant, no app registration, no way to perform an interactive
sign-in or MFA challenge, and no Graph API credentials - a hard
constraint. What *is* built: `scripts/ingest_real_export.py` (takes
exactly a raw export, runs it through the unmodified normalizer/pipeline,
`--label real_benign|real_controlled_attack`), `scripts/report_by_provenance.py`
(segmented metrics, never blended with synthetic numbers), and
[`real-lab-collection-guide.md`](real-lab-collection-guide.md) (the exact
steps to produce that export - a free Microsoft 365 Developer Program
tenant, Graph Explorer for a zero-setup JSON pull). All three are tested
against this project's own real-schema fixtures standing in for a
genuine export. The remaining gap is specifically: nobody has run those
steps against a real tenant yet.

---

# 3. Generate Real GitHub Audit Telemetry

Create a controlled GitHub organization or test environment and generate real developer activity.

Examples:

- repository creation
- repository cloning
- push activity
- permission changes
- organization membership changes
- personal access token usage
- API calls
- administrative events
- repository enumeration
- unusual access patterns

These events should also be processed through the real GitHub normalizer.

The purpose is to validate that the platform works against actual GitHub event structures rather than fixtures created internally.

**Status: infrastructure done; real data collection blocked on
credentials, not attempted as a substitute.** The `gh` CLI isn't
installed in this environment and there's no authenticated GitHub
session. GitHub's organization audit log API additionally requires GitHub
Enterprise Cloud (not available on free/Team org tiers) plus an
admin-scoped token - but [`real-lab-collection-guide.md`](real-lab-collection-guide.md)
documents a zero-cost path that doesn't need Enterprise (a personal
account's own security log export) alongside the Enterprise path for
anyone who has it. Same `scripts/ingest_real_export.py` /
`report_by_provenance.py` tooling as Entra - built and tested, just
waiting on a real export.

---

# 4. Preserve Real Schema Fidelity Testing

The real-schema validation work already found several important implementation errors.

These should remain documented as part of the project.

Examples discovered:

| Original Assumption | Real Vendor Behavior | Failure | Fix |
|---|---|---|---|
| Custom `category` field could safely drive Entra dispatch | Real Entra audit payloads also contain `category` (with unrelated real values) | Genuine payload could be misclassified or crash | Dispatch logic separated from that vendor field, keyed on `activityDateTime` vs. `createdDateTime` instead |
| GitHub used `country_code` | Real GitHub schema uses `country_name` | Country enrichment silently failed | Corrected field mapping |
| `mfaDetail` treated as current | Field is deprecated | Modern payloads could lose MFA context | Added `authenticationRequirement` as the documented replacement, with `mfaDetail` still checked first |
| `PartiallySucceeded` treated as failure | M365 explicitly distinguishes partial success | Incorrect normalization | Mapped to the schema's existing `partial` value |

This is valuable evidence that external schema validation was necessary.

The final project documentation should include this table and explain:

> Testing against officially published vendor payload structures exposed implementation assumptions that synthetic fixtures had failed to reveal.

**Status: done.** This table (and the full writeup) lives in
[`normalizer-fidelity.md`](normalizer-fidelity.md); the regression
fixtures stay in `tests/fixtures/real_samples/` and run on every CI build
via `tests/unit/test_normalizers_against_real_samples.py`.

---

# 5. Build a Noisy Benign Dataset

The current benign population is too clean.

A stronger dataset should deliberately contain legitimate behavior that resembles malicious activity: a traveling user, a legitimate administrator, a developer API burst, a new corporate laptop, service account activity, and a legitimate bulk download — each evaluated on full context (auth, device, OAuth, privilege, historical baseline) rather than any single signal in isolation.

**Status: done.** See [`evaluation.md`](evaluation.md)'s updated benign
dataset section.

---

# 6. Create a Frozen Holdout Dataset

The detector and synthetic generator were developed together, creating a risk of circular evaluation. A separate holdout dataset — new timing, ordering, personas, volumes, and attack combinations not directly copied from the original scenarios — should be generated once, frozen (never edited to improve scores), and tracked with an explicit original-result / observed-failure / engineering-change / new-result log.

**Status: done.** See [`holdout.md`](holdout.md).

---

# 7. Increase the Evaluation Scale

25–50 scenario variants per family / 150–300 malicious sequences are targets, not requirements — sized to what can be generated and validated realistically.

**Status: done**, scaled to a level that keeps the suite fast while
meaningfully increasing variety. See [`evaluation.md`](evaluation.md).

---

# 8. Run Multiple Evaluation Seeds

Report mean ± standard deviation across several independent seeds rather than relying on one deterministic run.

**Status: done.** See [`evaluation.md`](evaluation.md)'s multi-seed
section.

---

# 9. Preserve Atomic Alerts Alongside Correlation

A6 exposed an architectural point, not a defect: not every meaningful security event belongs to a multi-stage attack chain. Atomic detections and correlated incidents should both feed the analyst queue as complementary outputs.

**Status: done.** `GET /api/alerts` and the `/alerts` dashboard page
surface high-severity atomic matches as their own actionable queue,
alongside (not replaced by) `/incidents`.

---

# 10. Do Not Artificially "Fix" A6

Do not create a correlation rule simply to force A6's recall to 100% — that would weaken the evaluation. Document the result instead: A6 remained detectable through the atomic detection layer but was intentionally not promoted to a correlated incident because no supporting multi-stage identity sequence existed.

**Status: done, and staying done.** No correlation rule was added for
A6. See `app/evaluation/scenarios.py`'s `_make_a6` docstring and
[`evaluation.md`](evaluation.md).

---

# 11. Build a More Meaningful Baseline Comparison

Individual signals (new device, OAuth consent, repository enumeration, bulk download) may each be legitimate alone; the research value is in testing whether correlation detects the *combination* within a window while reducing false positives on the individually-benign singletons.

**Status: done.** See [`evaluation.md`](evaluation.md)'s ambiguous-signal
section.

---

# 12. Evaluation Metrics

Recall, precision, false-positive rate, F1, mean time to detect (atomic vs. correlated), alert reduction ratio, and per-attack-family scenario coverage.

**Status: done.** F1 and a proper correlation-layer false-positive rate
(previously only a count) were added to `app/evaluation/metrics.py`.

---

# 13. Target Research Question

> Can cross-event identity correlation reduce alert fragmentation and improve investigation context while maintaining useful detection coverage against realistic benign and malicious activity?

Secondary: can behavioral and temporal correlation distinguish malicious identity chains from isolated legitimate events more effectively than atomic rules alone?

**Status: done.** Adopted as the framing in
[`evaluation.md`](evaluation.md), alongside the original blueprint
research question (§2.1), which this restates rather than replaces.

---

# 14. Final Claims Must Match the Evidence

Avoid "IdentityTrace achieves 100% precision." Prefer "on the controlled synthetic evaluation set, IdentityTrace produced no false-positive correlated incidents." Final claims must distinguish synthetic, vendor-schema, live-lab, holdout, and external-telemetry validation.

**Status: done**, applied throughout `evaluation.md`, `holdout.md`, and
this document.

---

# 15. Desired Final Evaluation

```
Real Vendor Telemetry
        +
Real Lab Activity
        +
Noisy Benign Holdout Data
        +
Labeled Attack Scenarios
        ↓
Normalization → Atomic Detection → Correlation → Incident Generation
        ↓
Evaluation Harness → Metrics
```

**Status: partially done.** Everything except the top two inputs (real
vendor telemetry, real lab activity) is built and reproducible from the
repository. See "What's actually blocked" below.

---

## What's actually blocked, and what unblocks it

Items 2 and 3 need exactly one thing: **you run the collection yourself**
(a free Entra lab tenant via Microsoft 365 Developer Program, a free
GitHub account/org) and hand the raw export to
`scripts/ingest_real_export.py --label real_benign|real_controlled_attack`.
Full step-by-step instructions, with the lowest-friction path for each
vendor called out explicitly: [`real-lab-collection-guide.md`](real-lab-collection-guide.md).
That script runs every event through the real, unmodified normalizer and
full pipeline and reports a fidelity summary - events normalized
successfully vs. failed (with reasons), detections fired, incidents
formed - and `scripts/report_by_provenance.py` then reports metrics
segmented by exactly which export they came from, kept separate from the
synthetic harness's numbers. No manual rewriting into IdentityTrace's
schema happens anywhere in that path.

Until that happens, DoD items "Real Entra telemetry has been ingested
successfully" and "Real GitHub telemetry has been ingested successfully"
stay unchecked - honestly, not silently substituted with more synthetic
data relabeled as real.

## Phase 9 Definition of Done

- [x] Current IdentityTrace v1 state is committed
- [ ] Real Entra telemetry has been ingested successfully - **blocked, see above**
- [ ] Real GitHub telemetry has been ingested successfully - **blocked, see above**
- [x] Real vendor events pass through normalizers without manual rewriting (true for the schema-fidelity fixtures already in place; not yet exercised against a live export)
- [x] Real-schema regression fixtures remain tested
- [x] Noisy benign personas have been added
- [x] A frozen holdout dataset exists
- [x] Attack scenario variation has been increased
- [x] Evaluation runs across multiple seeds
- [x] Precision is reported
- [x] Recall is reported
- [x] F1 score is reported
- [x] False-positive rate is reported
- [x] Detection latency is reported
- [x] Alert reduction is reported
- [x] Results are reported per attack family
- [x] A6 remains honestly documented
- [x] Atomic alerts and correlated incidents are treated as complementary outputs
- [x] Final claims distinguish synthetic testing from real-world validation
- [x] Evaluation methodology is reproducible from the repository

## Final Goal

The project should ultimately be able to support a defensible statement such as:

> IdentityTrace was evaluated using synthetic attack scenarios, challenging benign holdout activity, real vendor-schema fixtures, and live lab telemetry. Atomic rules provided early individual detections, while the correlation layer grouped related evidence into higher-context incidents and reduced analyst alert volume. Testing also identified standalone attack behaviors that should remain atomic alerts rather than being forced into multi-stage correlations.

As of this phase, that statement is accurate **except** for "live lab
telemetry" - every other clause is backed by a reproducible result in
this repository. The objective was never perfect numbers; it was results
that are reproducible, measurable, realistic, transparent, defensible,
and useful to security analysts.
