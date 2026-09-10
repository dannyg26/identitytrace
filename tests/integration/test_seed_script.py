"""scripts/seed_demo_data.py is what a fresh clone runs to get something
real to look at - test it as an actual subprocess, the way a user runs
it, against a throwaway SQLite file."""

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_seed_script_populates_a_fresh_database(tmp_path):
    db_path = tmp_path / "seed_test.db"
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{db_path}")

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "seed_demo_data.py"),
            "--seed", "1",
            "--scenarios-per-type", "1",
            "--benign-identities", "1",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert "Seeded" in result.stdout
    assert db_path.exists()
