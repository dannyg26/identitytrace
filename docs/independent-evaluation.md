# Evaluating independent telemetry

The frozen holdout and multi-seed benchmarks are synthetic. Changing a seed or
adding a replay does not make them independently collected data. IdentityTrace includes
an offline evaluator for externally supplied telemetry and separately reviewed
workflow annotations. No customer data is uploaded by this tool.

## Freeze three files

| File | Content |
| --- | --- |
| `events.jsonl` | One normalized event or `{ "source": "entra", "raw": {...} }` envelope per line; stable event IDs and timestamps |
| `labels.json` | Workflow ID, verdict (`benign`, `malicious`, `unknown`) and event IDs, kept outside event payloads |
| `manifest.json` | Dataset ID, collection source, label reviewer, collection kind, SHA-256 hashes of both input files |

Example annotation and manifest (replace placeholder hashes with hashes of the
exact file bytes **after** collection and annotation are frozen):

```json
[{"workflow_id":"review-001","verdict":"unknown","event_ids":["event-001"]}]
```

```json
{
  "dataset_id": "review-batch-001",
  "source": "Describe collection provenance and the observation period",
  "label_reviewer": "Reviewer or team identifier",
  "collection_kind": "independently_collected",
  "events_sha256": "SHA256-OF-EVENTS-FILE",
  "labels_sha256": "SHA256-OF-LABELS-FILE"
}
```

Collection kind can also be `controlled_lab` or `synthetic`. It is a supplier
declaration, not proof of independence. The software checks file integrity and
annotation consistency; it cannot certify a reviewer's independence or honesty.
Unknown cases must stay unknown. Unannotated events supply historical context and
are excluded from workflow confusion counts. A workflow is a true positive when
at least one annotated event participates in a finding; annotate the suspicious
action events separately from benign historical context to avoid overstating recall.

```text
python scripts/evaluate_dataset.py --events events.jsonl --labels labels.json --manifest manifest.json --output result-new.json
```

The evaluator rejects changed hashes, duplicate events, overlapping workflow labels,
unknown event references and ground-truth fields in event envelopes. Only telemetry
enters the real pipeline in a disposable in-memory database; labels are consulted
after detection. Results contain workflow confusion counts, source breakdowns, Wilson
intervals and code/rule fingerprints. Existing results cannot be overwritten by the
CLI. Protect input and output files according to their data sensitivity.

## Study protocol before collecting results

1. Freeze the rules and a development-data inventory. Set the review criteria and
   evaluation units before inspecting detection results. Keep evaluation subjects,
   time periods and source files out of tuning data; record any known overlap.
2. Collect representative benign activity across time, users and supported sources.
   Add independently executed attack exercises with authorization and recorded
   outcomes. Do not infer compromise merely from a device-code or consent event.
3. Have a reviewer assess evidence without the detector's predictions. Record
   disagreements as unknown until adjudicated. Retain the original annotation history.
4. Freeze the three files, run once against the intended rule version, and publish
   false positives and missed attacks alongside successful cases. Report every
   source's sample count and uncertainty, including sources with no observations.
5. Keep any dataset used to fix a detection out of the next untouched evaluation.
   Record selection bias, correlated workflows and controlled-lab conditions.

No broader independently labeled customer corpus has been verified. This evaluator
provides infrastructure for that study; its availability does not establish
real-world detection accuracy.
