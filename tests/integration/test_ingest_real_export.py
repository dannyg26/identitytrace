"""scripts/ingest_real_export.py is the unblock path for real vendor
telemetry (Phase 9 #2/#3) - test it as a real subprocess against the
project's own real-schema fixtures (tests/fixtures/real_samples/), which
stand in for a genuine export without claiming to be one."""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "real_samples"


def _run(tmp_path, export_path, extra_args=()):
    db_path = tmp_path / "ingest_test.db"
    env = dict(os.environ, DATABASE_URL=f"sqlite:///{db_path}")
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "ingest_real_export.py"), str(export_path), *extra_args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result


def test_ingest_raw_graph_api_response_shape(tmp_path):
    """The exact raw body Microsoft Graph returns
    ({"@odata.context": ..., "value": [...]}) - pasted verbatim, no
    manual extraction of the `value` array required."""
    events = [
        json.loads((FIXTURES / "entra_signin_devicecode.json").read_text()),
        json.loads((FIXTURES / "entra_audit_oauth_consent.json").read_text()),
    ]
    export_path = tmp_path / "graph_response.json"
    export_path.write_text(json.dumps({
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns",
        "value": events,
    }))

    result = _run(tmp_path, export_path, ["--source", "entra", "--label", "real_benign"])

    assert result.returncode == 0, result.stderr
    assert "Normalized OK:       2" in result.stdout


def test_ingest_bare_list_with_forced_source(tmp_path):
    """A bare JSON list with no wrapper and no per-item 'source' - e.g. a
    GitHub audit-log API response."""
    events = [json.loads((FIXTURES / "github_audit_pat_clone.json").read_text())]
    export_path = tmp_path / "github_export.json"
    export_path.write_text(json.dumps(events))

    result = _run(tmp_path, export_path, ["--source", "github", "--label", "real_benign"])

    assert result.returncode == 0, result.stderr
    assert "Normalized OK:       1" in result.stdout


def test_ingest_newline_delimited_json(tmp_path):
    """GitHub's own personal security log "Export -> JSON" button, found
    via real Phase 9B collection, doesn't produce a bare list at all - it
    produces newline-delimited JSON (one object per line, no enclosing
    []), which a plain json.loads() rejects with 'Extra data'."""
    base_event = json.loads((FIXTURES / "github_audit_pat_clone.json").read_text())
    second_event = {**base_event, "_document_id": "second-line-event"}
    events = [base_event, second_event]
    export_path = tmp_path / "github_ndjson_export.json"
    export_path.write_text("\n".join(json.dumps(e) for e in events))

    result = _run(tmp_path, export_path, ["--source", "github", "--label", "real_benign"])

    assert result.returncode == 0, result.stderr
    assert "Normalized OK:       2" in result.stdout


def test_ingest_forced_source_export(tmp_path):
    events = [
        json.loads((FIXTURES / "entra_signin_devicecode.json").read_text()),
        json.loads((FIXTURES / "entra_audit_oauth_consent.json").read_text()),
    ]
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps({"source": "entra", "events": events}))

    result = _run(tmp_path, export_path, ["--label", "real_benign"])

    assert result.returncode == 0, result.stderr
    assert "Normalized OK:       2" in result.stdout
    assert "Failed to normalize: 0" in result.stdout

    provenance_path = export_path.with_suffix(".json.provenance.json")
    assert provenance_path.exists()
    provenance = json.loads(provenance_path.read_text())
    assert provenance["label"] == "real_benign"
    assert len(provenance["event_ids"]) == 2


def test_ingest_mixed_source_list(tmp_path):
    entra_event = json.loads((FIXTURES / "entra_signin_devicecode.json").read_text())
    github_event = json.loads((FIXTURES / "github_audit_pat_clone.json").read_text())
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps([
        {"source": "entra", "raw": entra_event},
        {"source": "github", "raw": github_event},
    ]))

    result = _run(tmp_path, export_path, ["--label", "real_benign"])

    assert result.returncode == 0, result.stderr
    assert "Normalized OK:       2" in result.stdout


def test_ingest_reports_failures_without_crashing(tmp_path):
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps({
        "source": "entra",
        "events": [{"id": "missing-required-fields"}],  # no createdDateTime
    }))

    result = _run(tmp_path, export_path, ["--label", "real_benign"])

    assert result.returncode == 0, result.stderr
    assert "Normalized OK:       0" in result.stdout
    assert "Failed to normalize: 1" in result.stdout


def test_label_is_required(tmp_path):
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps({"source": "entra", "events": []}))

    result = _run(tmp_path, export_path)  # no --label

    assert result.returncode != 0
    assert "--label" in result.stderr


def test_controlled_attack_requires_attack_type(tmp_path):
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps({"source": "entra", "events": []}))

    result = _run(tmp_path, export_path, ["--label", "real_controlled_attack"])

    assert result.returncode != 0
    assert "--attack-type" in result.stderr


def test_controlled_attack_provenance_records_attack_type(tmp_path):
    entra_event = json.loads((FIXTURES / "entra_signin_devicecode.json").read_text())
    export_path = tmp_path / "export.json"
    export_path.write_text(json.dumps({"source": "entra", "events": [entra_event]}))

    result = _run(
        tmp_path, export_path,
        ["--label", "real_controlled_attack", "--attack-type", "A2"],
    )

    assert result.returncode == 0, result.stderr
    provenance = json.loads(export_path.with_suffix(".json.provenance.json").read_text())
    assert provenance["label"] == "real_controlled_attack"
    assert provenance["attack_type"] == "A2"
