#!/usr/bin/env python
"""Generate the holdout dataset ONCE and write it to
tests/fixtures/holdout/holdout_v1.json.

Run this only to create a new holdout generation (holdout_v2, etc.) - not
as part of normal evaluation. Once a version is committed, it's frozen:
do not re-run this to overwrite an existing file to "fix" a result. See
docs/holdout.md for the freeze discipline this exists to support.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.evaluation.holdout import generate_holdout_dataset  # noqa: E402

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "holdout" / "holdout_v1.json"


def main() -> None:
    if OUTPUT_PATH.exists():
        print(f"{OUTPUT_PATH} already exists - refusing to overwrite a frozen holdout set.")
        print("Bump the version (holdout_v2.json) if you need a new one; see docs/holdout.md.")
        sys.exit(1)

    dataset = generate_holdout_dataset()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(dataset, indent=2), encoding="utf-8")

    n_benign = sum(len(s["events"]) for s in dataset["benign_sequences"])
    n_malicious = sum(
        1 for inst in dataset["attack_scenarios"] for e in inst["events"] if e["label"] == "malicious"
    )
    print(f"Wrote {OUTPUT_PATH}")
    print(f"  {len(dataset['benign_sequences'])} benign sequences ({n_benign} events)")
    print(f"  {len(dataset['attack_scenarios'])} attack scenarios ({n_malicious} malicious events)")


if __name__ == "__main__":
    main()
