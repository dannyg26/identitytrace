"""scripts/real_metrics_report.py reuses app.evaluation.metrics.compute_metrics
against real ingested telemetry - test the full ingest -> report pipeline
as real subprocesses, same pattern as test_report_by_provenance.py."""

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


def _metrics_report(env, provenance_paths):
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "real_metrics_report.py"), *map(str, provenance_paths)],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60,
    )


def test_full_metric_set_on_real_ingested_data(tmp_path):
    db_path = tmp_path / "metrics_test.db"
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

    result = _metrics_report(env, [
        benign_export.with_suffix(".json.provenance.json"),
        attack_export.with_suffix(".json.provenance.json"),
    ])

    assert result.returncode == 0, result.stderr
    metrics = json.loads(result.stdout.split("\n", 3)[-1])
    assert metrics["totals"]["benign_events"] == 1
    assert metrics["totals"]["malicious_events"] == 1
    assert metrics["scenario_coverage"]["A2"]["instances"] == 1
    assert "isolated_rule_baseline" in metrics
    assert "correlation_engine" in metrics
