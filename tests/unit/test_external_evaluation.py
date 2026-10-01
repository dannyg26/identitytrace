import hashlib
import json

import pytest

from app.evaluation.external import evaluate_frozen_dataset, load_frozen_inputs, workflow_metrics


def fixture_files(tmp_path, change=None):
    events = [dict(event_id=f"e{i}", timestamp=f"2026-09-01T09:{i * 5:02}:00Z",
                   source="entra", actor_id="alice", actor_type="user", result="success", **extra)
              for i, extra in enumerate([
                  {"event_type": "signin", "action": "login", "auth_protocol": "deviceCode"},
                  {"event_type": "oauth_consent", "action": "consent", "permissions": ["Files.Read.All"]},
                  {"event_type": "file_access", "action": "read", "resource_type": "mailbox"},
                  {"event_type": "signin", "action": "login"},
              ])]
    labels = [{"workflow_id": "attack", "verdict": "malicious", "event_ids": ["e0", "e1", "e2"]},
              {"workflow_id": "unknown", "verdict": "unknown", "event_ids": ["e3"]}]
    if change:
        change(events, labels)
    paths = [tmp_path / name for name in ("events.jsonl", "labels.json", "manifest.json")]
    paths[0].write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    paths[1].write_text(json.dumps(labels), encoding="utf-8")
    paths[2].write_text(json.dumps({"dataset_id": "test-only", "source": "unit fixture", "label_reviewer": "test author",
        "collection_kind": "synthetic", "events_sha256": hashlib.sha256(paths[0].read_bytes()).hexdigest(),
        "labels_sha256": hashlib.sha256(paths[1].read_bytes()).hexdigest()}), encoding="utf-8")
    return paths


def test_separate_labels_real_pipeline_and_unknowns(tmp_path):
    result = evaluate_frozen_dataset(*fixture_files(tmp_path))
    assert result["totals"] == {"events": 4, "workflows": 2, "unknown_workflows": 1, "unlabeled_context_events": 0}
    correlation = result["workflow_metrics"]["correlated"]
    assert correlation["tp"] == 1
    assert correlation["fp"] == correlation["tn"] == correlation["fn"] == 0
    assert correlation["false_positive_rate"] is None
    assert result["by_source"]["entra"]["correlated"] == correlation
    assert "app/pipeline.py" in result["implementation_files"]


def test_annotations_do_not_change_detector_output(tmp_path):
    first = evaluate_frozen_dataset(*fixture_files(tmp_path))
    second = evaluate_frozen_dataset(*fixture_files(tmp_path, lambda e, labels: labels[0].update(verdict="benign")))
    assert first["workflows"][0]["correlated"] == second["workflows"][0]["correlated"]
    assert second["workflow_metrics"]["correlated"]["fp"] == 1


def test_frozen_hash_rejects_edited_telemetry(tmp_path):
    paths = fixture_files(tmp_path)
    paths[0].write_text(paths[0].read_text() + "\n")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_frozen_inputs(*paths)


@pytest.mark.parametrize("change", [
    lambda e, labels: labels[0].update(event_ids=["missing"]),
    lambda e, labels: labels[1].update(event_ids=["e0"]),
    lambda e, labels: labels[0].update(event_ids=["e0", "e0"]),
    lambda e, labels: labels[0].update(verdict="probably okay"),
    lambda e, labels: e[0].update(label="malicious"),
    lambda e, labels: e[1].update(event_id="e0"),
    lambda e, labels: e[0].pop("event_id"),
])
def test_ambiguous_inputs_are_rejected(tmp_path, change):
    with pytest.raises(ValueError):
        load_frozen_inputs(*fixture_files(tmp_path, change))


def test_confusion_counts_and_empty_denominators():
    rows = [{"verdict": verdict, "hit": hit} for verdict in ("benign", "malicious", "unknown") for hit in (True, False)]
    result = workflow_metrics(rows, "hit")
    assert all(result[key] == 1 for key in ("tp", "fp", "tn", "fn"))
    assert result["f1"] == result["precision"] == result["recall"] == .5
    assert workflow_metrics([], "hit")["recall"] is None
