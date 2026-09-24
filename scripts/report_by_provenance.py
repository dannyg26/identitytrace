#!/usr/bin/env python
"""Report detection results segmented by exactly where the data came from -
real_benign / real_controlled_attack - never silently combined with the
synthetic evaluation harness's own numbers (those are a separate,
always-synthetic report - see app/evaluation/harness.py and
docs/evaluation.md).

Reads one or more provenance files written by scripts/ingest_real_export.py,
queries the app's LIVE database (whatever DATABASE_URL points at - the same
one those events were ingested into) for what actually fired against each
file's event_ids, and prints per-file and aggregated results.

Usage:
    python scripts/report_by_provenance.py export.json.provenance.json
    python scripts/report_by_provenance.py real_data/*.provenance.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.models.db import SessionLocal, init_db  # noqa: E402
from app.models.detection import DetectionMatchRecord  # noqa: E402
from app.models.incident import IncidentRecord  # noqa: E402


def _report_for_file(db, provenance: dict) -> dict:
    event_ids = set(provenance["event_ids"])
    matches = (
        db.query(DetectionMatchRecord)
        .filter(DetectionMatchRecord.event_id.in_(event_ids))
        .all()
        if event_ids else []
    )
    incidents = [
        i for i in db.query(IncidentRecord).all()
        if set(i.evidence_ids) & event_ids
    ]

    result = {
        "export_path": provenance["export_path"],
        "label": provenance["label"],
        "attack_type": provenance.get("attack_type"),
        "event_count": len(event_ids),
        "atomic_alerts": len(matches),
        "incidents": len(incidents),
    }

    if provenance["label"] == "real_benign":
        result["false_positive_alerts"] = len(matches)
        result["false_positive_incidents"] = len(incidents)
    else:  # real_controlled_attack
        result["detected_isolated_rule"] = bool(matches)
        result["detected_correlation"] = bool(incidents)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provenance_files", nargs="+", type=Path)
    args = parser.parse_args()

    init_db()  # tolerate running against a fresh/empty DATABASE_URL
    db = SessionLocal()
    try:
        results = []
        for path in args.provenance_files:
            provenance = json.loads(path.read_text(encoding="utf-8"))
            results.append(_report_for_file(db, provenance))
    finally:
        db.close()

    benign = [r for r in results if r["label"] == "real_benign"]
    attacks = [r for r in results if r["label"] == "real_controlled_attack"]

    print("=" * 70)
    print("REAL VENDOR TELEMETRY RESULTS (not synthetic - see docs/evaluation.md")
    print("for the always-synthetic harness numbers; these are kept separate)")
    print("=" * 70)

    print(f"\nreal_benign exports: {len(benign)}")
    for r in benign:
        print(
            f"  {r['export_path']}: {r['event_count']} events, "
            f"{r['false_positive_alerts']} false-positive alerts, "
            f"{r['false_positive_incidents']} false-positive incidents"
        )
    if benign:
        total_events = sum(r["event_count"] for r in benign)
        total_fp_alerts = sum(r["false_positive_alerts"] for r in benign)
        total_fp_incidents = sum(r["false_positive_incidents"] for r in benign)
        print(f"  TOTAL: {total_events} events, {total_fp_alerts} FP alerts, "
              f"{total_fp_incidents} FP incidents "
              f"(FP incident rate: {total_fp_incidents / len(benign):.3f} per export)")

    print(f"\nreal_controlled_attack exports: {len(attacks)}")
    for r in attacks:
        print(
            f"  {r['export_path']} ({r['attack_type']}): "
            f"isolated={'detected' if r['detected_isolated_rule'] else 'MISSED'}, "
            f"correlated={'detected' if r['detected_correlation'] else 'not correlated'}"
        )
    if attacks:
        recall_isolated = sum(r["detected_isolated_rule"] for r in attacks) / len(attacks)
        recall_correlated = sum(r["detected_correlation"] for r in attacks) / len(attacks)
        print(f"  Isolated-rule recall on real attacks:    {recall_isolated:.1%} ({len(attacks)} runs)")
        print(f"  Correlation-engine recall on real attacks: {recall_correlated:.1%} ({len(attacks)} runs)")

    if not results:
        print("\nNo provenance files given.")


if __name__ == "__main__":
    main()
