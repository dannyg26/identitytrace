"""Incident query, disposition, and correlation-rule wiring
(blueprint §9.2: GET/PATCH /incidents, GET /detections-equivalent for
correlation rules).

Mirrors app/api/detections.py's pattern: correlation rules load once at
startup into a module-level registry (`set_loaded_correlation_rules`) that
app/api/events.py reads from during ingestion, and that this router exposes
read-only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.correlation.schema import CorrelationRule
from app.graph.build import build_incident_graph
from app.graph.serialize import graph_to_dict
from app.incident_query import IncidentFilters, incident_query
from app.models.db import get_db
from app.models.incident import IncidentRecord
from app.models.operations import AuditRecord
from app.writes import write_lock

router = APIRouter(tags=["incidents"])

ALLOWED_STATUSES = {"open", "investigating", "resolved", "false_positive"}

_loaded_correlation_rules: list[CorrelationRule] = []


def set_loaded_correlation_rules(rules: list[CorrelationRule]) -> None:
    global _loaded_correlation_rules
    _loaded_correlation_rules = rules


def get_loaded_correlation_rules() -> list[CorrelationRule]:
    return _loaded_correlation_rules


class IncidentUpdate(BaseModel):
    expected_updated_at: Optional[datetime] = None
    status: Optional[str] = None
    analyst_disposition: Optional[str] = Field(default=None, max_length=200)
    notes: Optional[str] = Field(default=None, max_length=20000)


@router.get("/correlation-rules")
def list_correlation_rules() -> list[dict]:
    return [
        {
            "id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "version": rule.version,
            "enabled": rule.enabled,
            "window_seconds": rule.window_seconds,
            "sequence": rule.sequence,
            "score_bonus": rule.score_bonus,
            "classification": rule.classification,
            "severity_cap": rule.severity_cap,
            "escalation_deviations": rule.escalation_deviations,
            "scenario": rule.scenario,
            "attack": [a.model_dump() for a in rule.attack],
        }
        for rule in sorted(_loaded_correlation_rules, key=lambda r: r.id)
    ]


@router.get("/incidents")
def list_incidents(
    filters: IncidentFilters = Depends(),
    scenario: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> list[dict]:
    limit = max(1, min(limit, 1000))
    query = incident_query(db, filters)
    if scenario:
        query = query.filter(IncidentRecord.scenario == scenario)
    records = (
        query.order_by(IncidentRecord.last_event_at.desc())
        .offset(max(0, offset))
        .limit(limit)
        .all()
    )
    return [r.to_dict() for r in records]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> dict:
    record = db.get(IncidentRecord, incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"incident '{incident_id}' not found")
    return record.to_dict()


@router.get("/incidents/{incident_id}/graph")
def get_incident_graph(incident_id: str, db: Session = Depends(get_db)) -> dict:
    record = db.get(IncidentRecord, incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"incident '{incident_id}' not found")
    graph = build_incident_graph(db, record.to_dict())
    return graph_to_dict(graph)


@router.patch("/incidents/{incident_id}")
def patch_incident(
    incident_id: str, update: IncidentUpdate, request: Request, db: Session = Depends(get_db)
) -> dict:
    with write_lock(db):
        return _update_incident(incident_id, update, request, db)


def _update_incident(incident_id, update, request, db):
    record = db.get(IncidentRecord, incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"incident '{incident_id}' not found")

    def utc(value):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

    if update.expected_updated_at is not None and utc(update.expected_updated_at) != utc(record.updated_at):
        raise HTTPException(409, "This incident changed since you opened it. Reload before saving.")

    previous = {key: getattr(record, key) for key in ("status", "analyst_disposition", "notes")}
    if update.status is not None:
        if update.status not in ALLOWED_STATUSES:
            raise HTTPException(
                status_code=422,
                detail=f"status must be one of {sorted(ALLOWED_STATUSES)}",
            )
        record.status = update.status
    if update.analyst_disposition is not None:
        record.analyst_disposition = update.analyst_disposition
    if update.notes is not None:
        record.notes = update.notes

    record.updated_at = datetime.now(timezone.utc)
    db.add(AuditRecord(principal=request.state.principal.name, action="incident.updated",
                       entity_id=incident_id, before=previous,
                       after={key: getattr(record, key) for key in previous}))
    db.commit()
    return record.to_dict()
