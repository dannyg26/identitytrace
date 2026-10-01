"""Event ingestion and query API.

POST /events accepts either an already-normalized event, or a
{"source": ..., "raw": {...}} envelope that gets run through the matching
normalizer first. GET /events and GET /events/{id} make ingested events
queryable and traceable back to their raw evidence - the Phase 1 exit
criterion from the blueprint's roadmap.

Every ingested event is also run through the loaded atomic detection rules
(Phase 2) and against the identity's prior behavioral baseline (Phase 3);
matches and deviations are persisted, and GET /events/{id}/matches and
GET /events/{id}/deviations surface them alongside the raw evidence. Those
matches/deviations are then checked against every loaded correlation rule
(Phase 4) - a satisfied rule creates or updates an incident, surfaced at
GET /events/{id}/incidents.

The normalize -> baseline -> persist -> detect -> correlate pipeline
itself lives in app/pipeline.py, shared with the offline evaluation
harness (Phase 7) - this module only adds the HTTP-specific bits (status
codes, request/response models).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.detections import get_loaded_rules
from app.api.incidents import get_loaded_correlation_rules
from app.identity import resolve_identity
from app.models.baseline import BaselineDeviationRecord
from app.models.db import get_db
from app.models.detection import DetectionMatchRecord
from app.models.event import EventRecord, NormalizedEvent
from app.models.incident import IncidentRecord
from app.pipeline import EventConflictError, normalize_payload, process_event

router = APIRouter(tags=["events"])


def _normalize_payload(payload: dict[str, Any]) -> NormalizedEvent:
    """HTTP-status-coded wrapper around app.pipeline.normalize_payload."""
    try:
        return normalize_payload(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        # Unknown source - a request-shape problem, not a data problem.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=422, detail=f"failed to normalize raw event: {exc}"
        ) from exc


@router.post("/events", response_model=NormalizedEvent, status_code=201)
def ingest_event(
    payload: dict[str, Any] = Body(...), db: Session = Depends(get_db)
) -> NormalizedEvent:
    event = resolve_identity(db, _normalize_payload(payload))
    try:
        process_event(db, event, get_loaded_rules(), get_loaded_correlation_rules())
    except EventConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return event


@router.get("/events", response_model=list[NormalizedEvent])
def list_events(
    source: Optional[str] = None,
    actor_id: Optional[str] = None,
    event_type: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> list[NormalizedEvent]:
    limit = max(1, min(limit, 1000))
    query = db.query(EventRecord)
    if source:
        query = query.filter(EventRecord.source == source)
    if actor_id:
        query = query.filter(EventRecord.actor_id == actor_id)
    if event_type:
        query = query.filter(EventRecord.event_type == event_type)
    if since:
        query = query.filter(EventRecord.timestamp >= since)
    if until:
        query = query.filter(EventRecord.timestamp <= until)
    records = (
        query.order_by(EventRecord.timestamp.desc()).offset(offset).limit(limit).all()
    )
    return [r.to_schema() for r in records]


@router.get("/events/{event_id}", response_model=NormalizedEvent)
def get_event(event_id: str, db: Session = Depends(get_db)) -> NormalizedEvent:
    record = db.get(EventRecord, event_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"event '{event_id}' not found")
    return record.to_schema()


@router.get("/events/{event_id}/matches")
def get_event_matches(event_id: str, db: Session = Depends(get_db)) -> list[dict]:
    if db.get(EventRecord, event_id) is None:
        raise HTTPException(status_code=404, detail=f"event '{event_id}' not found")
    records = (
        db.query(DetectionMatchRecord)
        .filter(DetectionMatchRecord.event_id == event_id)
        .order_by(DetectionMatchRecord.score.desc())
        .all()
    )
    return [r.to_dict() for r in records]


@router.get("/events/{event_id}/deviations")
def get_event_deviations(event_id: str, db: Session = Depends(get_db)) -> list[dict]:
    if db.get(EventRecord, event_id) is None:
        raise HTTPException(status_code=404, detail=f"event '{event_id}' not found")
    records = (
        db.query(BaselineDeviationRecord)
        .filter(BaselineDeviationRecord.event_id == event_id)
        .order_by(BaselineDeviationRecord.weight.desc())
        .all()
    )
    return [r.to_dict() for r in records]


@router.get("/events/{event_id}/incidents")
def get_event_incidents(event_id: str, db: Session = Depends(get_db)) -> list[dict]:
    record = db.get(EventRecord, event_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"event '{event_id}' not found")
    # evidence_ids is a JSON list column - filtering it in SQL is backend-
    # specific, so scope to the identity (cheap, indexed) and filter in
    # Python. Incident volume per identity is small at this project's scale.
    candidates = db.query(IncidentRecord).filter(IncidentRecord.superseded_at.is_(None)).all()
    return [c.to_dict() for c in candidates if event_id in c.evidence_ids]
