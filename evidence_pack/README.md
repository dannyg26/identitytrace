# Evidence Pack

Generated evidence, organized into three tiers. See
[`docs/evidence-pack.md`](../docs/evidence-pack.md) for what each file is,
how it was produced, and how to reproduce it - this file only indexes them.

- `01_raw_vendor_evidence/` - real Microsoft Graph audit/sign-in exports,
  redacted for IPs, tenant domains, and tenant-specific object/event IDs.
  See the evidence guide for redaction limits and placeholder conventions.
- `02_processing_detection_evidence/` - what IdentityTrace's own pipeline
  did with that input (detection matches, incident records), queried from
  the app's database.
- `03_evaluation_results/` - metric sets from the evaluation harness and
  real-data reporting scripts.

The full, unredacted vendor corpus stays in the gitignored `real_data/` at
the repo root and is never committed.
