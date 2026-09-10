# Normalizer Fidelity Check

The user's own question prompted this: the evaluation harness
(`docs/evaluation.md`) is 100% synthetic - it tests whether this
project's *architecture* works, not whether it survives contact with
real-world telemetry. Integrating a real dataset (the blueprint's own
recommendation, §10.1.1: Splunk BOTS v2/v3) turned out to be impractical
here - both are distributed exclusively as pre-indexed Splunk databases
(320MB-16.4GB), requiring an actual running Splunk Enterprise instance to
extract anything; there's no plain-file export. Installing Splunk into
this project's dev environment for that purpose wasn't pursued.

Instead: every field name and enum value each normalizer
(`app/normalizers/{entra,github,m365}.py`) depends on was checked against
each source's real, officially-published API documentation, and every
normalizer was run against fixtures shaped like the real thing (not this
project's own invented shapes) - see `tests/fixtures/real_samples/`. This
doesn't replace real background-noise telemetry (still a documented gap -
see `docs/evaluation.md`), but it answers a real question the synthetic
harness can't: would this code actually parse a genuine tenant's export?

Checked 2026-09-10 against:
- Microsoft Graph API v1.0/beta: `signIn`, `directoryAudit`,
  `deviceDetail`, `signInLocation`, `targetResource`,
  `auditActivityInitiator` resource docs (learn.microsoft.com).
- GitHub's documented enterprise audit log schema and "Authentication
  Metadata for Git Events" feature (docs.github.com, github.blog).
- Office 365 Management Activity API common schema (learn.microsoft.com).

## Real bugs found and fixed

1. **`app/normalizers/entra.py`'s dispatch logic used an invented
   discriminator that collided with a real field.** `normalize()` picked
   the sign-in vs. audit parser based on a `category: "auditLogs" /
   "signInLogs"` marker this project made up. Real `directoryAudit`
   payloads have their *own* genuine `category` field
   (`"ApplicationManagement"`, `"RoleManagement"`, ...) - unrelated to
   picking a parser. A real audit payload would have been silently routed
   to the sign-in parser and crashed with `KeyError: 'createdDateTime'`.
   Fixed: dispatch now keys on `activityDateTime` (real, audit-only) vs.
   `createdDateTime` (real, sign-in-only) - two genuine, non-colliding
   fields, not an invented one.

2. **`app/normalizers/github.py` read the wrong field name for country.**
   Used `actor_location.country_code`; GitHub's documented field is
   `country_name` (a name like `"Russian Federation"`, not a 2-letter
   code - unlike Entra's `countryOrRegion`, which *is* a code. The two
   sources aren't directly comparable without extra work this project
   doesn't do). This bug was invisible before: a test fixture had the
   wrong field, but no test ever asserted on the resulting `geo_country`
   value - now fixed on both sides.

3. **`app/normalizers/entra.py` relied solely on a deprecated field for
   MFA strength.** `mfaDetail` is documented-deprecated on the real
   `signIn` resource. Its replacement, `authenticationRequirement`
   (`singleFactorAuthentication` / `multiFactorAuthentication`), is now
   checked as a fallback - `mfaDetail` still wins when present, since it's
   still commonly returned and is what every one of this project's own
   fixtures/generators produce.

4. **`app/normalizers/m365.py` discarded information this project's own
   schema already had a place for.** The real `ResultStatus:
   "PartiallySucceeded"` value was being folded into `"failure"`.
   `NormalizedEvent`'s `result` field has had a dedicated `"partial"`
   value since Phase 1 (`app/models/event.py`) - no normalizer had ever
   used it until this fix.

## What this does and doesn't change

- **The evaluation numbers in `docs/evaluation.md` are unaffected** -
  that harness uses its own synthetic generator
  (`app/evaluation/scenarios.py`), not these fixtures, and none of the
  four fixes change detection logic, scoring, or correlation.
- **What it does change**: this project's own scenario generator and two
  integration tests used the same invented `category` marker the bug fix
  above removed reliance on - updated to real field values
  (`ApplicationManagement`/`RoleManagement`) as part of this pass, so the
  synthetic generator itself is now also more schema-accurate, not just
  the parsers.
- **Limitation, stated plainly**: officially-published API docs give
  schemas (property tables), not full worked example payloads with
  realistic values - the *values* in `tests/fixtures/real_samples/*.json`
  (names, IPs, app names) are invented for readability. Every *field
  name* and *enum value* is real and cited; the surrounding data isn't
  claimed to be a genuine captured log.

## Testing

`tests/unit/test_normalizers_against_real_samples.py` - one test per
fixture, each asserting the specific thing that fixture was built to
prove (the deprecated-MFA fallback, the country field, the dispatch fix,
the `PartiallySucceeded` mapping) rather than just "does it not crash."
