"""Incident persistence (blueprint §8.2's incident object) and the
upsert rule that keeps analyst triage safe across re-correlation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.models.db import Base


class IncidentRecord(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String, primary_key=True)
    identity_id: Mapped[str] = mapped_column(String, index=True)
    severity: Mapped[str] = mapped_column(String, index=True)
    score: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)
    attack_chain: Mapped[list] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    attack_mapping: Mapped[list] = mapped_column(JSON, default=list)
    correlation_rule_id: Mapped[str] = mapped_column(String, index=True)
    correlation_rule_title: Mapped[str] = mapped_column(String)
    scenario: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    window_seconds: Mapped[int] = mapped_column(Integer)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    score_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    evidence_reasons: Mapped[list] = mapped_column(JSON, default=list)
    # "attack_chain" | "workflow_review" (see app/correlation/schema.py).
    # NULL on incidents stored before this column existed = attack_chain.
    classification: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    # Why the severity is what it is for a workflow_review incident: the cap,
    # whether it applied, and any independent escalation evidence. NULL for
    # attack_chain incidents.
    escalation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String, default="open", index=True)
    analyst_disposition: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    superseded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    superseded_reason: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "identity_id": self.identity_id,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.confidence,
            "attack_chain": self.attack_chain,
            "evidence_ids": self.evidence_ids,
            "attack_mapping": self.attack_mapping,
            "correlation_rule_id": self.correlation_rule_id,
            "correlation_rule_title": self.correlation_rule_title,
            "scenario": self.scenario,
            "window_seconds": self.window_seconds,
            "first_event_at": self.first_event_at,
            "last_event_at": self.last_event_at,
            "score_breakdown": self.score_breakdown,
            "confidence_breakdown": self.confidence_breakdown,
            "evidence_reasons": self.evidence_reasons,
            "classification": self.classification or "attack_chain",
            "escalation": self.escalation,
            "status": self.status,
            "analyst_disposition": self.analyst_disposition,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "superseded_at": self.superseded_at,
            "superseded_reason": self.superseded_reason,
        }


_MUTABLE_FIELDS = (
    "identity_id",
    "severity",
    "score",
    "confidence",
    "attack_chain",
    "evidence_ids",
    "attack_mapping",
    "correlation_rule_title",
    "scenario",
    "window_seconds",
    "first_event_at",
    "last_event_at",
    "score_breakdown",
    "confidence_breakdown",
    "evidence_reasons",
    "classification",
    "escalation",
)


def upsert_incident(db: Session, payload: dict) -> IncidentRecord:
    """Create the incident, or refresh its evidence/score in place.

    Deliberately preserves `status`, `analyst_disposition`, and `notes` on
    an existing incident - an analyst's triage must never be silently reset
    just because the same chain re-satisfies the correlation rule (e.g. a
    later, unrelated event for the same identity falls inside the window
    again). Only a fresh incident gets the "open" default.
    """
    now = datetime.now(timezone.utc)
    existing = db.get(IncidentRecord, payload["incident_id"])

    if existing is not None:
        existing.superseded_at = None
        existing.superseded_reason = None
        for field in _MUTABLE_FIELDS:
            setattr(existing, field, payload[field])
        existing.updated_at = now
        return existing

    record = IncidentRecord(
        incident_id=payload["incident_id"],
        correlation_rule_id=payload["correlation_rule_id"],
        status="open",
        analyst_disposition=None,
        notes=None,
        created_at=now,
        updated_at=now,
        **{field: payload[field] for field in _MUTABLE_FIELDS},
    )
    db.add(record)
    return record
