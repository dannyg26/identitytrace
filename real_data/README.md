# real_data/

Put your real Entra/GitHub exports and their `.provenance.json` files
here. **Everything in this directory except this README is gitignored** -
real tenant IDs, real user emails, real tokens must never reach git.

See [`../docs/phase9b-first-collection-checklist.md`](../docs/phase9b-first-collection-checklist.md)
for exactly what to put here and how to name it. Suggested layout:

```
real_data/
├── entra_benign_day1.json
├── entra_benign_day1.json.provenance.json   (written by ingest_real_export.py)
├── entra_a2_attack.json
├── entra_a2_attack.json.provenance.json
├── github_benign.json
└── github_benign.json.provenance.json
```

Run everything from the repo root, e.g.:

```bash
python scripts/ingest_real_export.py real_data/entra_benign_day1.json \
    --source entra --label real_benign

python scripts/report_by_provenance.py real_data/*.provenance.json
```
