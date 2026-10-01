"""The core per-event pipeline: normalize -> baseline -> persist -> detect
-> correlate.

Shared by the live ingestion API (app/api/events.py) and the offline
evaluation harness (app/evaluation/) so what gets *evaluated* is exactly
what gets *deployed* - not a separate reimplementation that could quietly
drift out of sync. This module has no FastAPI/HTTP dependency on purpose:
`normalize_payload` raises plain Python exceptions (ValueError, KeyError,
TypeError, pydantic's ValidationError) and leaves turning those into HTTP
status codes to the API layer.
"""

from __future__ import annotations

from datetime import timezone
from itertools import groupby
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.baselines.deviation import evaluate_deviations
from app.baselines.profile import IdentityProfile, build_profile, extend_profile
from app.correlation.run import run_correlation_for_actor
from app.correlation.schema import CorrelationRule
from app.detections.engine import evaluate_event
from app.detections.schema import DetectionRule
from app.identity import resolve_identity
from app.models.baseline import BaselineDeviationRecord
from app.models.detection import DetectionMatchRecord
from app.models.event import EventRecord, NormalizedEvent
from app.models.incident import IncidentRecord, upsert_incident
from app.models.operations import AuditRecord, BaselineState
from app.normalizers import entra, github, m365
from app.writes import write_lock

NORMALIZERS = {
    "entra": entra.normalize,
    "github": github.normalize,
    "m365": m365.normalize,
}


class EventConflictError(ValueError):
    """An event ID was reused with different evidence."""


def normalize_payload(payload: dict[str, Any]) -> NormalizedEvent:
    """Accept either an already-normalized event, or a
    {"source": ..., "raw": {...}} envelope routed through the matching
    normalizer. Raises ValueError for an unknown source, KeyError/TypeError
    for a raw payload a normalizer can't parse, or pydantic's
    ValidationError for an invalid already-normalized payload.
    """
    if "raw" in payload and "source" in payload:
        source = payload["source"]
        normalizer = NORMALIZERS.get(source)
        if normalizer is None:
            raise ValueError(
                f"no normalizer registered for source '{source}' "
                f"(known: {sorted(NORMALIZERS)})"
            )
        return normalizer(payload["raw"])

    return NormalizedEvent(**payload)


def process_event(
    db: Session,
    event: NormalizedEvent,
    rules: list[DetectionRule],
    correlation_rules: list[CorrelationRule],
) -> None:
    with write_lock(db):
        _process_event(db, event, rules, correlation_rules)


def _process_event(db, event, rules, correlation_rules):
    """Run one already-normalized event through the full pipeline and
    persist everything it produces: the event itself, any Phase 2 rule
    matches, any Phase 3 baseline deviations, and any Phase 4 incidents
    those matches/deviations complete.
    """
    try:
        event = resolve_identity(db, event)
        existing = db.get(EventRecord, event.event_id)
        if existing is not None:
            # to_schema normalizes SQLite's naive UTC timestamps before comparison.
            if existing.to_schema() != event:
                raise EventConflictError(
                    f"event '{event.event_id}' already exists with different content"
                )
            db.commit()
            return  # An identical retry must not mutate evidence or analyst triage.

        state = db.get(BaselineState, event.actor_id)
        latest = state.last_timestamp if state else db.query(func.max(EventRecord.timestamp)).filter(
            EventRecord.actor_id == event.actor_id
        ).scalar()
        late = latest is not None and event.timestamp <= _utc(latest)
        profile = (IdentityProfile.model_validate(state.profile) if state and not late
                   else build_profile(db, event.actor_id, before=event.timestamp))
        db.add(EventRecord.from_schema(event))
        # Persist the parent first, including on databases enforcing foreign keys.
        db.flush()
        if late:
            rebuild_evidence(db, rules, correlation_rules, reason="Late event changed historical evidence")
            db.commit()
            return
        for match in evaluate_event(event, rules):
            db.add(DetectionMatchRecord.from_match(match))
        for deviation in evaluate_deviations(event, profile):
            db.add(BaselineDeviationRecord.from_deviation(event, deviation))

        # Queries in this same transaction can see flushed signals. Committing
        # here would leave partial evidence behind if correlation subsequently fails.
        db.flush()
        for incident_payload in run_correlation_for_actor(
            db, event.actor_id, as_of=event.timestamp, rules=correlation_rules
        ):
            upsert_incident(db, incident_payload)
            db.flush()
        extend_profile(profile, event)
        db.merge(BaselineState(actor_id=event.actor_id, last_timestamp=event.timestamp,
                               profile=profile.model_dump(mode="json")))
        db.commit()
    except Exception:
        db.rollback()
        raise


def _utc(timestamp):
    return timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp


def rebuild_evidence(db, rules, correlation_rules, reason="Identity links changed"):
    """Deterministically replay derived evidence without deleting investigations.

    Caller owns the transaction and writer lock. Full replay is intentionally an
    exceptional path; normal chronological ingestion uses baseline checkpoints.
    Equal-timestamp events all see the same strictly-earlier baseline.
    """
    from datetime import datetime

    events = [resolve_identity(db, row.to_schema()) for row in db.query(EventRecord).order_by(
        EventRecord.timestamp, EventRecord.event_id
    ).all()]
    db.query(BaselineDeviationRecord).delete(synchronize_session="fetch")
    db.query(DetectionMatchRecord).delete(synchronize_session="fetch")
    db.query(BaselineState).delete(synchronize_session="fetch")
    profiles = {}
    for _, group in groupby(events, key=lambda event: event.timestamp):
        batch = list(group)
        for event in batch:
            db.merge(EventRecord.from_schema(event))
            profile = profiles.setdefault(event.actor_id, IdentityProfile(actor_id=event.actor_id))
            for deviation in evaluate_deviations(event, profile):
                db.add(BaselineDeviationRecord.from_deviation(event, deviation))
            for match in evaluate_event(event, rules):
                db.add(DetectionMatchRecord.from_match(match))
        for event in batch:
            extend_profile(profiles[event.actor_id], event)
    for actor, profile in profiles.items():
        db.add(BaselineState(actor_id=actor, last_timestamp=profile.last_seen,
                             profile=profile.model_dump(mode="json")))
    db.flush()
    found = set()
    for event in events:
        for payload in run_correlation_for_actor(db, event.actor_id, event.timestamp, correlation_rules):
            upsert_incident(db, payload)
            found.add(payload["incident_id"])
            db.flush()
    for incident in db.query(IncidentRecord).filter(IncidentRecord.superseded_at.is_(None)).all():
        if incident.incident_id not in found:
            incident.superseded_at = datetime.now(timezone.utc)
            incident.superseded_reason = reason
            db.add(AuditRecord(principal="system", action="incident.superseded",
                               entity_id=incident.incident_id, after={"reason": reason}))
