"""Evaluate frozen JSONL telemetry plus separate workflow labels in an isolated database."""

import argparse
import json
from pathlib import Path

from app.evaluation.external import evaluate_frozen_dataset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("events", "labels", "manifest", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists; use a new file to preserve earlier evidence")
    result = evaluate_frozen_dataset(args.events, args.labels, args.manifest)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result["workflow_metrics"], indent=2))


if __name__ == "__main__":
    main()
