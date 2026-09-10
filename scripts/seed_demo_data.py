#!/usr/bin/env python
"""Populate the app's own (live) database with the same reproducible
benign+attack dataset the evaluation harness generates - so a fresh
clone has something real to click through in the dashboard immediately,
without needing to run a live attack simulation by hand.

Usage:
    python scripts/seed_demo_data.py [--seed N] [--scenarios-per-type N]

Run this BEFORE starting the server (or while it's stopped) - it opens
the same SQLite file `uvicorn app.main:app` would use (DATABASE_URL, or
./identitytrace.db by default). Unlike the evaluation harness
(app/evaluation/harness.py), which always runs against a throwaway
in-memory database, this script deliberately writes to the real one -
that's the point: give the dashboard something to show.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.correlation.loader import load_correlation_rules  # noqa: E402
from app.detections.loader import load_rules  # noqa: E402
from app.evaluation import scenarios as scen  # noqa: E402
from app.evaluation.harness import DEFAULT_BASE_TIME  # noqa: E402
from app.models.db import SessionLocal, init_db  # noqa: E402
from app.pipeline import normalize_payload, process_event  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--scenarios-per-type", type=int, default=2)
    parser.add_argument("--benign-identities", type=int, default=5)
    args = parser.parse_args()

    import random

    rng = random.Random(args.seed)

    generated = list(scen.generate_benign_population(rng, DEFAULT_BASE_TIME, args.benign_identities))
    generated += scen.generate_benign_edge_cases(rng, DEFAULT_BASE_TIME)
    instances = scen.generate_attack_scenarios(rng, DEFAULT_BASE_TIME, args.scenarios_per_type)
    for instance in instances:
        generated.extend(instance.events)
    generated.sort(key=lambda e: e.timestamp)

    init_db()
    db = SessionLocal()
    rules = load_rules()
    correlation_rules = load_correlation_rules()

    try:
        for item in generated:
            event = normalize_payload(item.payload)
            process_event(db, event, rules, correlation_rules)
    finally:
        db.close()

    n_malicious = sum(1 for i in instances for e in i.events if e.label == "malicious")
    print(f"Seeded {len(generated)} events ({n_malicious} malicious across {len(instances)} scenarios).")
    print("Start the app and open http://127.0.0.1:8000/incidents to explore.")


if __name__ == "__main__":
    main()
