#!/usr/bin/env python
"""Ingest a real vendor telemetry export through the unmodified pipeline
and report a fidelity summary.

This is the unblock path for Phase 9 items #2/#3 (real Entra/GitHub
telemetry): this environment has no Azure/Entra tenant, no GitHub
authentication, and no credentials to generate that telemetry itself (see
docs/phase9-external-evaluation.md). Anyone who *can* collect a real
export - a Graph API pull of signIns/directoryAudits, a GitHub
organization audit log export - can hand it to this script as-is. It does
NOT rewrite events into IdentityTrace's schema before ingestion; each
event goes through app.pipeline.normalize_payload() exactly like a live
POST /api/events call would.

Input format: a JSON file containing any of:
  - a bare list of raw vendor event objects (e.g. GitHub's security-log
    JSON export, or a GitHub audit-log API response) - pass --source
  - the exact raw response body Microsoft Graph returns
    ({"@odata.context": ..., "value": [...]}) - paste it verbatim, no
    manual extraction needed; pass --source
  - {"source": "entra"|"github"|"m365", "events": [...]}
    (source applies to every event in the file; omit per-event `source`)
  - a list of {"source": ..., "raw": {...}} envelopes (mixed sources)
  - newline-delimited JSON - one raw vendor event object per line, no
    enclosing [] (this is what GitHub's personal security log's own
    "Export -> JSON" button actually produces) - pass --source

Usage:
    python scripts/ingest_real_export.py export.json --source entra --label real_benign
    python scripts/ingest_real_export.py export.json --source entra \
        --label real_controlled_attack --attack-type A2

Writes ingested events to the app's real database (DATABASE_URL, or
./identitytrace.db) - unlike the evaluation harness, which always uses a
throwaway in-memory DB. That's deliberate: a real export is exactly what
you want sitting in the live app afterward, not discarded.

--label is required and is never guessed: every export is either entirely
genuine background activity (real_benign) or one controlled, lab-only
attack simulation (real_controlled_attack - every event in the file is
treated as ground truth for that one attack run, so keep benign and
attack activity in separate export files). Like the synthetic harness's
own labels (app/evaluation/scenarios.py), ground truth is written to a
*separate* provenance file next to the export - never into the events
themselves - so it can be used for reporting (scripts/report_by_provenance.py)
without ever being visible to the detection path.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pydantic import ValidationError  # noqa: E402

from app.correlation.loader import load_correlation_rules  # noqa: E402
from app.detections.loader import load_rules  # noqa: E402
from app.models.db import SessionLocal, init_db  # noqa: E402
from app.pipeline import normalize_payload, process_event  # noqa: E402


def _extract_raw_items(data) -> tuple[list, "str | None"]:
    """Accept whatever shape the file turns out to be in. Returns
    (raw_items, source_hint) - source_hint is a file-level default, not
    necessarily present."""
    if isinstance(data, dict):
        if "events" in data:
            return data["events"], data.get("source")
        if "value" in data:
            # The exact raw response body Microsoft Graph returns
            # ({"@odata.context": ..., "value": [...]}) - Graph never
            # tells you what "source" it is, so this always needs --source.
            return data["value"], None
        raise ValueError("dict input must have an 'events' or 'value' key")

    if isinstance(data, list):
        return data, None

    raise ValueError("expected a JSON list, or a dict with 'events' or 'value'")


def _parse_export_document(text: str):
    """Most sources produce one JSON document (a list, or a dict with
    'events'/'value'). GitHub's personal security log "Export -> JSON"
    (found via Phase 9B real telemetry) instead produces newline-delimited
    JSON - one object per line, no enclosing [] at all - which a plain
    json.loads() rejects with "Extra data"."""
    stripped = text.strip()
    if not stripped:
        return []
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return [json.loads(line) for line in stripped.splitlines() if line.strip()]


def _load_payloads(path: Path, forced_source: str | None) -> list[dict]:
    data = _parse_export_document(path.read_text(encoding="utf-8"))
    raw_items, source_hint = _extract_raw_items(data)

    payloads = []
    for item in raw_items:
        if forced_source:
            payloads.append({"source": forced_source, "raw": item})
        elif isinstance(item, dict) and "raw" in item and "source" in item:
            payloads.append(item)  # mixed-source envelope list
        elif isinstance(item, dict) and "source" in item and "raw" not in item:
            payloads.append(item)  # already-normalized event dict
        elif source_hint:
            payloads.append({"source": source_hint, "raw": item})
        else:
            raise ValueError(
                "no source determined for an item - pass --source, or use "
                "{'source': ..., 'events': [...]}: " + repr(item)[:200]
            )
    return payloads


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export_path", type=Path, help="JSON file of raw vendor events")
    parser.add_argument(
        "--source",
        choices=["entra", "github", "m365"],
        help="Force this source for every event (overrides per-event/file source)",
    )
    parser.add_argument(
        "--label",
        required=True,
        choices=["real_benign", "real_controlled_attack"],
        help="Ground truth for every event in this file - see the module docstring",
    )
    parser.add_argument(
        "--attack-type",
        choices=["A1", "A2", "A3", "A4", "A5", "A6"],
        help="Which blueprint scenario this controlled attack simulates (only meaningful with --label real_controlled_attack)",
    )
    parser.add_argument(
        "--provenance-out",
        type=Path,
        help="Where to write the provenance record (default: <export_path>.provenance.json)",
    )
    args = parser.parse_args()

    if args.label == "real_controlled_attack" and not args.attack_type:
        parser.error("--attack-type is required when --label is real_controlled_attack")

    payloads = _load_payloads(args.export_path, args.source)

    init_db()
    db = SessionLocal()
    rules = load_rules()
    correlation_rules = load_correlation_rules()

    normalized_ok = 0
    failures: list[tuple[int, str]] = []
    ingested_event_ids: list[str] = []

    try:
        for i, payload in enumerate(payloads):
            try:
                event = normalize_payload(payload)
            except (KeyError, TypeError, ValueError, ValidationError) as exc:
                failures.append((i, f"{type(exc).__name__}: {exc}"))
                continue
            process_event(db, event, rules, correlation_rules)
            normalized_ok += 1
            ingested_event_ids.append(event.event_id)
    finally:
        db.close()

    print(f"Loaded:              {len(payloads)} events from {args.export_path}")
    print(f"Normalized OK:       {normalized_ok}")
    print(f"Failed to normalize: {len(failures)}")
    if failures:
        print("\nFailures (index, reason):")
        for i, reason in failures[:25]:
            print(f"  [{i}] {reason}")
        if len(failures) > 25:
            print(f"  ... and {len(failures) - 25} more")

    provenance_path = args.provenance_out or args.export_path.with_suffix(
        args.export_path.suffix + ".provenance.json"
    )
    provenance = {
        "label": args.label,
        "attack_type": args.attack_type,
        "export_path": str(args.export_path),
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "event_ids": ingested_event_ids,
        "failed_count": len(failures),
    }
    provenance_path.write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    print(f"\nProvenance record written: {provenance_path}")
    print(
        "Run scripts/report_by_provenance.py against this file (and any others) for "
        "metrics segmented by exactly where the data came from - never silently "
        "combined with the synthetic evaluation harness's own numbers."
    )
    print(
        "\nOr check GET /api/matches, /api/incidents, and the dashboard directly for "
        "what fired against this data."
    )


if __name__ == "__main__":
    main()
