"""scripts/report_by_provenance.py segments detection results by exactly
where the data came from (real_benign / real_controlled_attack) - test
the full ingest -> report pipeline as real subprocesses."""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "real_samples"


def _ingest(env, export_path, extra_args):
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "ingest_real_export.py"), str(export_path), *extra_args],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60,
    )


def _report(env, provenance_paths):
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "report_by_provenance.py"), *map(str, provenance_paths)],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60,
    )


def test_report_segments_benign_and_attack_exports(tmp_path):
    db_path = tmp_path / "report_test.db"
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{db_path}")

    benign_export = tmp_path / "benign.json"
    benign_export.write_text(json.dumps({
        "source": "entra",
        "events": [json.loads((FIXTURES / "entra_signin_devicecode.json").read_text())],
    }))
    attack_export = tmp_path / "attack.json"
    attack_export.write_text(json.dumps({
        "source": "entra",
        "events": [json.loads((FIXTURES / "entra_audit_oauth_consent.json").read_text())],
    }))

    r1 = _ingest(env, benign_export, ["--label", "real_benign"])
    assert r1.returncode == 0, r1.stderr
    r2 = _ingest(env, attack_export, ["--label", "real_controlled_attack", "--attack-type", "A2"])
    assert r2.returncode == 0, r2.stderr

    report = _report(env, [
        benign_export.with_suffix(".json.provenance.json"),
        attack_export.with_suffix(".json.provenance.json"),
    ])

    assert report.returncode == 0, report.stderr
    assert "real_benign exports: 1" in report.stdout
    assert "real_controlled_attack exports: 1" in report.stdout
    assert "REAL VENDOR TELEMETRY RESULTS" in report.stdout
    assert "(A2)" in report.stdout


def test_report_with_no_files_does_not_crash(tmp_path):
    db_path = tmp_path / "empty.db"
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{db_path}")
    # argparse requires at least one positional; give a nonexistent-but-valid
    # path is not appropriate here since it would raise on read - instead
    # verify the "no results" branch via an empty-events provenance file.
    provenance = tmp_path / "empty.provenance.json"
    provenance.write_text(json.dumps({
        "label": "real_benign", "attack_type": None, "export_path": "empty.json",
        "event_ids": [], "failed_count": 0,
    }))
    result = _report(env, [provenance])
    assert result.returncode == 0, result.stderr
    assert "real_benign exports: 1" in result.stdout
