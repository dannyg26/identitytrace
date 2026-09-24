#!/usr/bin/env python
"""Report workflow_review incidents (IDT-CORR-006) under BOTH semantics.

(A) Attack detector - an incident is a true positive only if its evidence
    comes from a real_controlled_attack export, a false positive if it comes
    only from real_benign exports. This is the ORIGINAL evaluation claim and
    is reported unchanged: it is the evidence that the rule cannot infer
    intent.
(B) Risky-workflow detector - an incident is a correct detection if the
    workflow it names really occurred, checked against the RAW vendor fields
    of its evidence events (not against the rule's own signals). Whether the
    workflow was malicious is deliberately left "unresolved".

Ground truth is the collection log (provenance labels) plus the raw
telemetry; there is no other. With two collected chains this is a
demonstration of the semantics, not a precision estimate.

Usage:
    python scripts/report_workflow_semantics.py real_data/*.provenance.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.models.db import SessionLocal, init_db  # noqa: E402
from app.models.event import EventRecord  # noqa: E402
from app.models.incident import IncidentRecord  # noqa: E402

ADD_GRANT = "add delegated permission grant"


def _raw(records: dict, event_id: str) -> dict:
    record = records.get(event_id)
    return (record.raw_event_ref or {}) if record else {}


def workflow_confirmed_from_raw(evidence_ids: list[str], records: dict) -> bool:
    """block (errorCode 90094) -> add-grant audit -> success (errorCode 0) by
    the same user, read straight from the vendor payloads."""
    if len(evidence_ids) != 3:
        return False
    block, grant, success = (_raw(records, e) for e in evidence_ids)
    return (
        (block.get("status") or {}).get("errorCode") == 90094
        and (grant.get("activityDisplayName") or "").lower() == ADD_GRANT
        and (success.get("status") or {}).get("errorCode") == 0
        and block.get("userPrincipalName") == success.get("userPrincipalName")
    )


def summarize(db, provenances: list[dict]) -> dict:
    label_of: dict[str, set[str]] = {}
    for p in provenances:
        for event_id in p["event_ids"]:
            label_of.setdefault(event_id, set()).add(p["label"])

    incidents = (
        db.query(IncidentRecord)
        .filter(IncidentRecord.classification == "workflow_review")
        .order_by(IncidentRecord.first_event_at)
        .all()
    )
    rows = []
    for inc in incidents:
        records = {
            r.event_id: r
            for r in db.query(EventRecord).filter(EventRecord.event_id.in_(inc.evidence_ids)).all()
        }
        labels = set().union(*(label_of.get(e, set()) for e in inc.evidence_ids))
        rows.append({
            "incident_id": inc.incident_id,
            "identity": inc.identity_id,
            "severity": inc.severity,
            "score": inc.score,
            "provenance": sorted(labels),
            "attack_labelled": "real_controlled_attack" in labels,
            "workflow_confirmed_from_raw": workflow_confirmed_from_raw(inc.evidence_ids, records),
            "escalated": bool((inc.escalation or {}).get("escalated")),
        })

    tp = sum(1 for r in rows if r["attack_labelled"])
    fp = len(rows) - tp
    confirmed = sum(1 for r in rows if r["workflow_confirmed_from_raw"])
    return {
        "incidents": rows,
        "A_attack_detector": {
            "true_positive_incidents": tp,
            "false_positive_incidents": fp,
            "precision": round(tp / len(rows), 3) if rows else None,
        },
        "B_risky_workflow_detector": {
            "workflow_incidents": len(rows),
            "workflow_confirmed_from_raw": confirmed,
            "precision": round(confirmed / len(rows), 3) if rows else None,
            "malicious_intent": "unresolved by telemetry; requires analyst/context escalation",
            "incidents_with_independent_escalation_evidence": sum(1 for r in rows if r["escalated"]),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("provenance_files", nargs="+", type=Path)
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    provenances = [json.loads(p.read_text(encoding="utf-8")) for p in args.provenance_files]
    print(json.dumps(summarize(db, provenances), indent=2))
    db.close()


if __name__ == "__main__":
    main()
