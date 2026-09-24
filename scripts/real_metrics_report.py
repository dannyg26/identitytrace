#!/usr/bin/env python
"""Compute the full evaluation metric set (precision, recall, F1, FPR,
detection latency, alert-reduction ratio, per-scenario, per-provenance)
against REAL ingested telemetry, reusing app.evaluation.metrics.compute_metrics
- the exact same tested formulas the synthetic harness uses - so real and
synthetic numbers are directly comparable and never computed two
different ways by accident.

This is deliberately separate from scripts/report_by_provenance.py, which
stays the quick per-file benign/attack sanity check. This script is the
"re-run after expanded collection" tool: point it at every real
provenance file and it reports the same metric set docs/evaluation.md's
synthetic sections use.

Usage:
    python scripts/real_metrics_report.py real_data/*.provenance.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.evaluation.metrics import compute_metrics  # noqa: E402
from app.evaluation.scenarios import BenignSequence, GeneratedEvent, ScenarioInstance  # noqa: E402
from app.models.db import SessionLocal, init_db  # noqa: E402
from app.models.event import EventRecord  # noqa: E402


def _event_timestamps(db, event_ids: set[str]) -> dict[str, datetime]:
    if not event_ids:
        return {}
    records = db.query(EventRecord).filter(EventRecord.event_id.in_(event_ids)).all()
    out = {}
    for r in records:
        ts = r.timestamp
        out[r.event_id] = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("provenance_files", nargs="+", type=Path)
    args = parser.parse_args()

    init_db()
    db = SessionLocal()

    provenances = [json.loads(p.read_text(encoding="utf-8")) for p in args.provenance_files]
    benign_prov = [p for p in provenances if p["label"] == "real_benign"]
    attack_prov = [p for p in provenances if p["label"] == "real_controlled_attack"]

    benign_event_ids: set[str] = set()
    for p in benign_prov:
        benign_event_ids |= set(p["event_ids"])
    malicious_event_ids: set[str] = set()
    for p in attack_prov:
        malicious_event_ids |= set(p["event_ids"])

    all_ts = _event_timestamps(db, benign_event_ids | malicious_event_ids)

    scenarios: list[ScenarioInstance] = []
    for p in attack_prov:
        ids = set(p["event_ids"])
        ts_values = [all_ts[i] for i in ids if i in all_ts]
        if not ts_values:
            print(f"WARNING: no events found in DB for {p['export_path']} - skipping from scenario metrics", file=sys.stderr)
            continue
        start_time = min(ts_values)
        events = [
            GeneratedEvent(payload={}, event_id=eid, timestamp=all_ts.get(eid, start_time), label="malicious")
            for eid in ids
        ]
        scenarios.append(ScenarioInstance(
            scenario_id=Path(p["export_path"]).stem,
            attack_type=p.get("attack_type") or "UNKNOWN",
            identity="real",
            start_time=start_time,
            events=events,
        ))

    benign_sequences = [
        BenignSequence(
            sequence_id=Path(p["export_path"]).stem,
            persona="real",
            identity="real",
            events=[
                GeneratedEvent(payload={}, event_id=eid, timestamp=all_ts.get(eid, datetime.now(timezone.utc)), label="benign")
                for eid in p["event_ids"]
            ],
        )
        for p in benign_prov
    ]

    metrics = compute_metrics(
        db, scenarios, malicious_event_ids, benign_event_ids, benign_sequences,
    )
    db.close()

    print("=" * 70)
    print("REAL VENDOR TELEMETRY - FULL METRIC SET (not synthetic)")
    print("=" * 70)
    print(json.dumps(metrics, indent=2, default=str))


if __name__ == "__main__":
    main()
