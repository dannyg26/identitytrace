"""Turn a CorrelationHit into the blueprint's incident object (§8.2)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.correlation.engine import CorrelationHit
from app.correlation.scoring import (
    compute_confidence,
    compute_incident_score,
    score_ceiling_for_severity,
    severity_for_score,
)
from app.models.baseline import BaselineDeviationRecord
from app.models.event import EventRecord


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _escalation_evidence(db: Session, hit: CorrelationHit, event_ids: list[str]) -> list[dict]:
    """Baseline deviations on the chain's own events whose type the rule
    names as independent escalation evidence. Deviations already part of the
    matched sequence are skipped - they are scored as chain signals."""
    rule = hit.rule
    if not rule.escalation_deviations:
        return []
    in_chain = {(s.event_id, s.signal_type) for s in hit.matched_signals if s.kind == "deviation"}
    rows = (
        db.query(BaselineDeviationRecord)
        .filter(BaselineDeviationRecord.event_id.in_(event_ids))
        .filter(BaselineDeviationRecord.deviation_type.in_(rule.escalation_deviations))
        .order_by(BaselineDeviationRecord.timestamp, BaselineDeviationRecord.deviation_type)
        .all()
    )
    return [
        {
            "event_id": r.event_id,
            "actor_id": r.actor_id,
            "deviation_type": r.deviation_type,
            "weight": r.weight,
            "reason": r.reason,
        }
        for r in rows
        if (r.event_id, r.deviation_type) not in in_chain
    ]


def build_incident_payload(db: Session, hit: CorrelationHit) -> dict:
    chain = hit.matched_signals
    rule = hit.rule

    event_risk = sum(s.weight for s in chain if s.kind == "detection")
    behavioral_deviation = sum(s.weight for s in chain if s.kind == "deviation")
    event_ids = _dedupe_preserve_order([s.event_id for s in chain])

    escalation: dict | None = None
    score_breakdown_extra: dict = {}
    if rule.classification == "workflow_review":
        evidence = _escalation_evidence(db, hit, event_ids)
        behavioral_deviation += sum(e["weight"] for e in evidence)
        score = compute_incident_score(event_risk, behavioral_deviation, rule.score_bonus)
        escalated = bool(evidence)
        cap_applied = False
        if not escalated:
            ceiling = score_ceiling_for_severity(rule.severity_cap)
            if score > ceiling:
                score_breakdown_extra["uncapped_score"] = score
                score = ceiling
                cap_applied = True
        escalation = {
            "severity_cap": rule.severity_cap,
            "escalated": escalated,
            "cap_applied": cap_applied,
            "qualifying_deviation_types": list(rule.escalation_deviations),
            "evidence": evidence,
        }
    else:
        score = compute_incident_score(event_risk, behavioral_deviation, rule.score_bonus)
    severity = severity_for_score(score)

    span_seconds = (chain[-1].timestamp - chain[0].timestamp).total_seconds()
    correlation_strength = (
        max(0.0, 1 - (span_seconds / rule.window_seconds)) if rule.window_seconds else 0.0
    )
    evidence_quality = min(1.0, len(rule.sequence) / 4)

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
            **score_breakdown_extra,
        },
        "classification": rule.classification,
        "escalation": escalation,
        "confidence_breakdown": {
            "correlation_strength": round(correlation_strength, 2),
            "evidence_quality": round(evidence_quality, 2),
            "telemetry_completeness": round(telemetry_completeness, 2),
        },
        "evidence_reasons": [
            {
                "signal_type": s.signal_type,
                "event_id": s.event_id,
                # Who performed this step - essential on cross-identity
                # chains, where the consent step belongs to the admin, not
                # to the incident's requesting identity.
                "actor_id": s.actor_id,
                "kind": s.kind,
                "label": s.label,
                "weight": s.weight,
                # ISO string, not a datetime - this list is stored in a JSON
                # column (stdlib json.dumps, no datetime support), unlike
                # first_event_at/last_event_at which are real DateTime columns.
                "timestamp": s.timestamp.isoformat(),
                **({"entity": s.entity} if s.entity else {}),
            }
            for s in chain
        ],
    }
