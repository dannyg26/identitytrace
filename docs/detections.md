# Detection Library

14 versioned, atomic (single-event, L1) detection rules, defined as YAML
under `detections/{entra,github,m365,cross_domain}/` and validated against
`app/detections/schema.py`. Live view: `GET /api/detections` (JSON) or the
`/rules` dashboard page (also shows last-triggered timestamps).

Each rule evaluates one event. Per-identity history is handled by the
[baseline layer](baselines.md), and cross-event sequences are handled by
[correlation](correlation.md).

## Rule engine

A rule's `match` is a list of `Condition`s (`{op, field, value|values}`),
ANDed together - all must pass for the rule to fire. Supported operators:
`equals`, `not_equals`, `in`, `not_in`, `any_of`, `all_of`, `contains`,
`contains_any`, `not_null`, `gt`, `gte`, `lt`, `lte`. See
`app/detections/engine.py`. Every match records a human-readable reason per
condition (blueprint §7.2's design rule: "every point added to risk must
have a human-readable reason").

## Rules

| ID | Title | Severity | Score | Scenario | ATT&CK |
|---|---|---|---|---|---|
| IDT-ENTRA-001 | Risky OAuth consent scope granted | medium | 35 | A2 | T1550.001 |
| IDT-ENTRA-002 | OAuth consent grants offline_access | high | 45 | A2 | T1528 |
| IDT-ENTRA-003 | Successful native-client (non-browser) sign-in - `nativeClient` (derived from `clientAppUsed`) or legacy `deviceCode`; v3, see evaluation.md | low | 15 | A1 | T1621 |
| IDT-ENTRA-004 | Interactive sign-in succeeded without MFA | medium | 30 | A3 | T1078 |
| IDT-ENTRA-005 | Legacy/basic authentication protocol used | medium | 25 | A3 | T1110 |
| IDT-ENTRA-006 | Privileged role assignment | high | 50 | A5 | T1098 |
| IDT-ENTRA-007 | Sign-in blocked pending admin consent (`errorCode 90094` only) | low | 15 | A2 | T1550.001 |
| IDT-GITHUB-001 | PAT used for repository access | low | 15 | A4 | T1550 |
| IDT-GITHUB-002 | Large repository clone via PAT | high | 55 | A4 | T1213 |
| IDT-GITHUB-003 | Token accessed a sensitive-named repository | high | 50 | A4 | T1552 |
| IDT-GITHUB-004 | PAT carries admin-level org scope | high | 45 | A4 | T1098 |
| IDT-XDOMAIN-001 | Bulk data transfer, any source | high | 50 | A6 | T1030 |
| IDT-XDOMAIN-002 | Successful access to a sensitive resource type | medium | 30 | A6 | T1552 |
| IDT-M365-001 | Mailbox forwarding/inbox rule created | high | 45 | A6 | T1114.003 |

Every scenario in the threat-model catalog (A1-A6, see
[`threat-model.md`](threat-model.md)) has at least one rule feeding it - the
foundation used by temporal correlation to form multi-signal incidents.

## Testing

- `tests/detection/test_engine.py` - the generic condition evaluator, rule
  filtering (`source`/`event_type`/`enabled`), and reason recording, all
  independent of any specific rule.
- `tests/detection/test_rules.py` - loads the real shipped YAML and runs one
  positive + at least two negative cases per rule (blueprint §10.4's
  "Detection tests" requirement), plus a coverage guard that fails if a new
  rule is added without test cases.
- `tests/unit/test_detection_loader.py` - YAML validation, duplicate-id
  rejection, and malformed-rule rejection.

## Adding a rule

1. Add a YAML file under the right `detections/<source>/` subdirectory (or
   `cross_domain/` for source-agnostic rules) with a unique `id`.
2. Add its positive + negative cases to `tests/detection/test_rules.py` -
   `test_every_loaded_rule_has_test_coverage` fails the build otherwise.
3. Restart the app (rules load once at startup, by design - see
   `app/api/detections.py`).

## Consent scopes are scored on what the grant added

`IDT-ENTRA-001` and `IDT-ENTRA-002` read `permissions`. For a real
`DelegatedPermissionGrant.Scope` change, that list is the scopes the event
*added* (`newValue` minus `oldValue`), not the cumulative scope the grant now
holds - otherwise every later grant would re-fire on permissions granted in
earlier events (e.g. `offline_access`). The cumulative value remains in the
event's `raw_event_ref`. See docs/evaluation.md, "A2 Benign Twin — Detection
vs Intent".

An Entra `Remove delegated permission grant` record (the bookkeeping half of an
update, logged ~1 ms after its `Add` with identical values) grants nothing and carries no
permissions, so one consent action is scored once. See docs/evaluation.md, "`Remove
delegated permission grant`: an update artifact, not a revocation".

## Signal tagging for correlation

Each rule carries an optional `signal:` field naming the semantic event
category it represents for temporal correlation (e.g. both
`IDT-ENTRA-001` and `IDT-ENTRA-002` tag `risky_oauth_consent`). Defaults to
the rule's own id if untagged. See [`correlation.md`](correlation.md).

## Known limitation

Rules still score independently at the atomic level - correlation
chains matches across events into incidents, but nothing here suppresses
duplicate/expected noise at the rule level itself. Documented
false-positive exceptions remain a documented limitation.
