"""Evaluate frozen external telemetry with labels kept out of the detection pipeline."""

import hashlib
import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.correlation.loader import load_correlation_rules
from app.detections.loader import load_rules
from app.evaluation.statistics import wilson_interval
from app.models.db import Base
from app.models.detection import DetectionMatchRecord
from app.models.incident import IncidentRecord
from app.pipeline import normalize_payload, process_event
from app.resources import resource_directory


def fingerprint(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_frozen_inputs(events_path, labels_path, manifest_path):
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("Manifest must be a JSON object")
    for field in ("dataset_id", "source", "label_reviewer", "collection_kind"):
        if not isinstance(manifest.get(field), str) or not manifest[field].strip():
            raise ValueError(f"Manifest requires {field}")
    if manifest["collection_kind"] not in {"synthetic", "controlled_lab", "independently_collected"}:
        raise ValueError("Invalid collection_kind")
    for key, path in (("events_sha256", events_path), ("labels_sha256", labels_path)):
        if manifest.get(key) != fingerprint(path):
            raise ValueError(f"Frozen input hash mismatch: {key}")
    events = []
    for line in Path(events_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError("Every telemetry line must be a JSON object")
        if set(payload) & {"label", "ground_truth", "attack_id", "attack_type"}:
            raise ValueError("Ground-truth fields belong in the separate labels file")
        event = normalize_payload(payload)
        if event != normalize_payload(payload):
            raise ValueError("Every input needs a stable vendor or normalized event ID and timestamp")
        events.append(event)
    known = {e.event_id for e in events}
    if not events or len(known) != len(events):
        raise ValueError("Input must contain events with unique IDs")
    labels = json.loads(Path(labels_path).read_text(encoding="utf-8"))
    if not isinstance(labels, list) or not labels:
        raise ValueError("Labels must be a nonempty list of workflow annotations")
    assigned, workflows = set(), set()
    for label in labels:
        if not isinstance(label, dict):
            raise ValueError("Every annotation must be a JSON object")
        if not isinstance(label.get("workflow_id"), str) or not label["workflow_id"].strip():
            raise ValueError("Every annotation needs a workflow_id")
        if label["workflow_id"] in workflows:
            raise ValueError("Duplicate workflow_id")
        workflows.add(label["workflow_id"])
        if label.get("verdict") not in {"benign", "malicious", "unknown"}:
            raise ValueError("Verdict must be benign, malicious or unknown")
        ids = label.get("event_ids")
        if not isinstance(ids, list) or not ids or any(not isinstance(i, str) for i in ids):
            raise ValueError("Every workflow needs event_ids")
        if len(set(ids)) != len(ids) or not set(ids) <= known or set(ids) & assigned:
            raise ValueError("Event labels overlap, repeat, or reference absent evidence")
        assigned.update(ids)
    return events, labels, manifest


def workflow_metrics(rows, layer):
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for row in rows:
        if row["verdict"] == "unknown":
            continue
        positive = row["verdict"] == "malicious"
        counts[("t" if row[layer] == positive else "f") + ("p" if row[layer] else "n")] += 1
    tp, fp, tn, fn = (counts[k] for k in ("tp", "fp", "tn", "fn"))
    def ratio(n, d):
        return round(n / d, 4) if d else None
    return {**counts, "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "false_positive_rate": ratio(fp, fp + tn), "f1": ratio(2 * tp, 2 * tp + fp + fn),
            "recall_wilson_95": wilson_interval(tp, tp + fn),
            "false_positive_rate_wilson_95": wilson_interval(fp, fp + tn)}


def evaluate_frozen_dataset(events_path, labels_path, manifest_path):
    events, labels, manifest = load_frozen_inputs(events_path, labels_path, manifest_path)
    rules, correlations = load_rules(), load_correlation_rules()
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            # Only telemetry enters the pipeline. Annotations are consulted after detection.
            for event in sorted(events, key=lambda e: (e.timestamp, e.event_id)):
                process_event(db, event, rules, correlations)
            atomic = {m.event_id for m in db.query(DetectionMatchRecord).all()}
            incidents = db.query(IncidentRecord).filter(IncidentRecord.superseded_at.is_(None)).all()
            correlated = {eid for incident in incidents for eid in incident.evidence_ids}
    finally:
        engine.dispose()
    sources = {e.event_id: e.source for e in events}
    rows = [{"workflow_id": label["workflow_id"], "verdict": label["verdict"],
             "sources": "+".join(sorted({sources[eid] for eid in label["event_ids"]})),
             "isolated": bool(set(label["event_ids"]) & atomic),
             "correlated": bool(set(label["event_ids"]) & correlated)} for label in labels]
    def metrics(items):
        return {layer: workflow_metrics(items, layer) for layer in ("isolated", "correlated")}
    app_root = Path(__file__).resolve().parents[1]
    files = {"app/" + p.relative_to(app_root).as_posix(): fingerprint(p) for p in sorted(app_root.rglob("*.py"))}
    for folder in ("detections", "correlations"):
        root = resource_directory(folder)
        files.update({folder + "/" + p.relative_to(root).as_posix(): fingerprint(p) for p in sorted(root.rglob("*.yaml"))})
    assigned = {eid for label in labels for eid in label["event_ids"]}
    return {"manifest": manifest, "manifest_sha256": fingerprint(manifest_path), "implementation_files": files,
            "totals": {"events": len(events), "workflows": len(rows),
                       "unknown_workflows": sum(r["verdict"] == "unknown" for r in rows),
                       "unlabeled_context_events": len(events) - len(assigned)},
            "workflow_metrics": metrics(rows),
            "by_source": {source: metrics([r for r in rows if r["sources"] == source]) for source in sorted({r["sources"] for r in rows})},
            "workflows": rows,
            "limitations": ["Collection kind and reviewer are supplier declarations, not verified independence.",
                            "Unknown workflows and unlabeled context are excluded from confusion counts.",
                            "A workflow is detected if any of its annotated events participates in a finding.",
                            "Intervals describe sample uncertainty; correlated workflows and selection bias limit generalization."]}
