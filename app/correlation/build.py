"""Turn a CorrelationHit into the blueprint's incident object (§8.2)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.correlation.engine import CorrelationHit
from app.correlation.scoring import (
    compute_confidence,
    compute_incident_score,
    severity_for_score,
)
from app.models.event import EventRecord


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def build_incident_payload(db: Session, hit: CorrelationHit) -> dict:
    chain = hit.matched_signals
    rule = hit.rule

    event_risk = sum(s.weight for s in chain if s.kind == "detection")
    behavioral_deviation = sum(s.weight for s in chain if s.kind == "deviation")
    score = compute_incident_score(event_risk, behavioral_deviation, rule.score_bonus)
    severity = severity_for_score(score)

    span_seconds = (chain[-1].timestamp - chain[0].timestamp).total_seconds()
    correlation_strength = (
        max(0.0, 1 - (span_seconds / rule.window_seconds)) if rule.window_seconds else 0.0
    )
    evidence_quality = min(1.0, len(rule.sequence) / 4)

    event_ids = _dedupe_preserve_order([s.event_id for s in chain])
    records = {
        r.event_id: r
        for r in db.query(EventRecord).filter(EventRecord.event_id.in_(event_ids)).all()
    }
    with_evidence = sum(1 for eid in event_ids if records.get(eid) and records[eid].raw_event_ref)
    telemetry_completeness = with_evidence / len(event_ids) if event_ids else 0.0

    confidence = compute_confidence(correlation_strength, evidence_quality, telemetry_completeness)

    return {
        "incident_id": f"{rule.id}:{chain[0].event_id}",
        "identity_id": chain[0].actor_id,
        "severity": severity,
        "score": score,
        "confidence": confidence,
        "attack_chain": [s.signal_type for s in chain],
        "evidence_ids": event_ids,
        "attack_mapping": [a.model_dump() for a in rule.attack],
        "correlation_rule_id": rule.id,
        "correlation_rule_title": rule.title,
        "scenario": rule.scenario,
        "window_seconds": rule.window_seconds,
        "first_event_at": chain[0].timestamp,
        "last_event_at": chain[-1].timestamp,
        "score_breakdown": {
            "event_risk": event_risk,
            "behavioral_deviation": behavioral_deviation,
            "temporal_chain_bonus": rule.score_bonus,
        },
        "confidence_breakdown": {
            "correlation_strength": round(correlation_strength, 2),
            "evidence_quality": round(evidence_quality, 2),
            "telemetry_completeness": round(telemetry_completeness, 2),
        },
        "evidence_reasons": [
            {
                "signal_type": s.signal_type,
                "event_id": s.event_id,
                "kind": s.kind,
                "label": s.label,
                "weight": s.weight,
                # ISO string, not a datetime - this list is stored in a JSON
                # column (stdlib json.dumps, no datetime support), unlike
                # first_event_at/last_event_at which are real DateTime columns.
                "timestamp": s.timestamp.isoformat(),
            }
            for s in chain
        ],
    }
