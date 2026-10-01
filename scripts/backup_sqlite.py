"""Create a consistent SQLite backup and verify its integrity. Never overwrite."""

import argparse
import hashlib
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


def backup(source: Path, destination: Path):
    source, destination = source.resolve(strict=True), destination.resolve()
    if source == destination:
        raise ValueError("Backup must be a different file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL closes the check/create race and also refuses existing symlinks.
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as src:
        with closing(sqlite3.connect(destination)) as target:
            src.backup(target)
            if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Backup integrity check failed")
    return {"created_at": datetime.now(timezone.utc).isoformat(),
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "bytes": destination.stat().st_size, "integrity": "ok"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    result = backup(args.source, args.destination)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
