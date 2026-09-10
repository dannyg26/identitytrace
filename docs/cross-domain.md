# Cross-Domain Expansion (Phase 6)

Adds Microsoft 365 (SharePoint/OneDrive/Exchange) as a third normalized
telemetry source, per the blueprint's suggested MVP-to-portfolio expansion
(§3.3, §6.1, §10.1.1) - Entra + GitHub for the MVP, one more SaaS/cloud
source for "portfolio-grade v1."

## What's new

- `app/normalizers/m365.py` - normalizes the real Office 365 Management
  Activity API audit schema (`CreationTime`, `Operation`, `Workload`,
  `UserId`, `ObjectId`, `ResultStatus`, ...) into `NormalizedEvent`. Feeds
  A6 (SaaS data theft) most directly: file download/access volume and
  mailbox persistence.
- `detections/m365/mailbox_forwarding_rule.yaml` (`IDT-M365-001`) - a new
  inbox rule or mailbox config change, the classic BEC persistence
  technique (forward/hide mail so it keeps working after a password
  reset). Tagged signal `mailbox_persistence` for future correlation rules.

## The point of this phase, demonstrated

Adding a third source required **zero changes** to the detection engine,
baseline engine, correlation engine, incident model, or any dashboard
page - only a normalizer and one domain-specific rule. Better still: the
source-agnostic rules from Phase 2 (`IDT-XDOMAIN-001` bulk transfer,
`IDT-XDOMAIN-002` sensitive resource type) immediately apply to m365
telemetry with no new code at all, because they were written against the
normalized schema, not against any one source's raw shape. This is exactly
the architectural bet the blueprint's thesis makes (§1: normalize first,
detect once) - Phase 6 is where that bet gets tested against a source the
detections were never written with in mind, and it holds.

One real event even fires two independent rules for a genuinely
overlapping reason: an Exchange inbox-rule change is tagged
`resource_type="mailbox"` (it's a mailbox configuration action), so it
satisfies both `IDT-M365-001` (the specific mailbox-rule check) and
`IDT-XDOMAIN-002` (any successful access to a sensitive resource type) -
two complementary pieces of evidence, not a bug. See
`tests/integration/test_event_pipeline.py::test_m365_source_flows_through_the_full_pipeline`.

## What's NOT here

AWS CloudTrail (the blueprint's other suggested cloud source, §17) isn't
added - one additional domain beyond Entra + GitHub is enough to prove the
normalization architecture holds, and adding a fourth wouldn't teach
anything the third one hasn't already. `app_id` on m365 events maps to
`ApplicationId` if a raw event happens to carry one, but no OAuth-consent-
style m365 events are modeled - that path stays on `entra.py`, since Azure
AD app consent audit events (which a real M365 tenant's unified log also
contains) are already covered there.

## Testing

- `tests/unit/test_normalizers.py` - file download, mailbox rule change,
  and failed-operation mapping.
- `tests/detection/test_rules.py` - `IDT-M365-001`'s positive/negative
  cases, same pattern as every other rule.
- `tests/integration/test_event_pipeline.py` - the cross-domain reuse
  claim above, verified against the real ingestion path.
