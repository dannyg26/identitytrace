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

from typing import Any

from sqlalchemy.orm import Session

from app.baselines.deviation import evaluate_deviations
from app.baselines.profile import build_profile
from app.correlation.run import run_correlation_for_actor
from app.correlation.schema import CorrelationRule
from app.detections.engine import evaluate_event
from app.detections.schema import DetectionRule
from app.models.baseline import BaselineDeviationRecord
from app.models.detection import DetectionMatchRecord
from app.models.event import EventRecord, NormalizedEvent
from app.models.incident import upsert_incident
from app.normalizers import entra, github, m365

NORMALIZERS = {
    "entra": entra.normalize,
    "github": github.normalize,
    "m365": m365.normalize,
}


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
    """Run one already-normalized event through the full pipeline and
    persist everything it produces: the event itself, any Phase 2 rule
    matches, any Phase 3 baseline deviations, and any Phase 4 incidents
    those matches/deviations complete.
    """
    # Build the identity's baseline from events strictly before this one -
    # before inserting the event, so the profile never includes the event
    # it's about to be compared against.
    profile = build_profile(db, event.actor_id, before=event.timestamp)

    record = EventRecord.from_schema(event)
    db.merge(record)

    for match in evaluate_event(event, rules):
        db.merge(DetectionMatchRecord.from_match(match))

    for deviation in evaluate_deviations(event, profile):
        db.merge(BaselineDeviationRecord.from_deviation(event, deviation))

    # Matches/deviations must be committed before correlation queries them
    # back out (app/correlation/signals.py reads from the DB) - this
    # event's own signals need to already be visible to participate in a
    # chain.
    db.commit()

    for incident_payload in run_correlation_for_actor(
        db, event.actor_id, as_of=event.timestamp, rules=correlation_rules
    ):
        upsert_incident(db, incident_payload)
    db.commit()
