"""Write a reproducible multi-seed benchmark artifact without touching the live DB."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.evaluation.harness import run_multi_seed_evaluation  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, nargs="+", default=[11, 29, 47, 71, 101])
    parser.add_argument("--scenarios-per-type", type=int, default=2)
    parser.add_argument("--benign-identities", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (len(args.seeds) > 20 or len(set(args.seeds)) != len(args.seeds)
            or not 1 <= args.scenarios_per_type <= 10 or not 1 <= args.benign_identities <= 20):
        parser.error("Use 1-20 distinct seeds, 1-10 scenarios per type and 1-20 benign identities")
    if args.output.exists():
        parser.error("Output already exists; choose a new file to preserve the previous experiment")
    result = run_multi_seed_evaluation(args.seeds, args.scenarios_per_type, args.benign_identities)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"Saved {len(args.seeds)} benchmark runs to {args.output}")


if __name__ == "__main__":
    main()
