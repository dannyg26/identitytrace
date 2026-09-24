"""Unify Phase 2 detection matches and Phase 3 baseline deviations into one
stream of "signals" - the vocabulary correlation sequences are written
against (a detection rule's `signal` tag, or a deviation's `deviation_type`
verbatim - e.g. "new_device" is already a signal name, no tagging needed).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.models.baseline import BaselineDeviationRecord
from app.models.detection import DetectionMatchRecord
from app.models.event import EventRecord


@dataclass
class SignalOccurrence:
    signal_type: str
    timestamp: datetime
    event_id: str
    actor_id: str
    kind: str  # "detection" | "deviation"
    source_id: str  # rule_id or deviation_type
    weight: int  # score (detection) or weight (deviation)
    label: str  # human-readable title/reason, for evidence display
    # Shared entity of the underlying event (e.g. its service_principal_id),
    # only populated by get_signals_in_window - the per-actor path has no
    # use for it. None means "no entity", never "matches anything".
    entity: Optional[str] = None


def get_signals_for_actor(
    db: Session, actor_id: str, since: datetime, until: datetime
) -> list[SignalOccurrence]:
    """All signals for one identity within [since, until], oldest first."""
    signals: list[SignalOccurrence] = []

    matches = (
        db.query(DetectionMatchRecord)
        .filter(DetectionMatchRecord.actor_id == actor_id)
        .filter(DetectionMatchRecord.timestamp >= since)
        .filter(DetectionMatchRecord.timestamp <= until)
        .all()
    )
    for m in matches:
        signals.append(
            SignalOccurrence(
                signal_type=m.signal,
                timestamp=m.timestamp,
                event_id=m.event_id,
                actor_id=m.actor_id,
                kind="detection",
                source_id=m.rule_id,
                weight=m.score,
                label=m.title,
            )
        )

    deviations = (
        db.query(BaselineDeviationRecord)
        .filter(BaselineDeviationRecord.actor_id == actor_id)
        .filter(BaselineDeviationRecord.timestamp >= since)
        .filter(BaselineDeviationRecord.timestamp <= until)
        .all()
    )
    for d in deviations:
        signals.append(
            SignalOccurrence(
                signal_type=d.deviation_type,
                timestamp=d.timestamp,
                event_id=d.event_id,
                actor_id=d.actor_id,
                kind="deviation",
                source_id=d.deviation_type,
                weight=d.weight,
                label=d.reason,
            )
        )

    signals.sort(key=lambda s: s.timestamp)
    return signals


def get_signals_in_window(
    db: Session,
    since: datetime,
    until: datetime,
    signal_types: set[str],
    entity_field: Optional[str] = None,
) -> list[SignalOccurrence]:
    """Signals of the given types from ALL identities within [since, until],
    oldest first - the input entity-bridged correlation needs, because its
    chain deliberately spans more than one actor.

    `entity_field` names an EventRecord column (e.g. "service_principal_id")
    copied onto each signal as `.entity`, so the matcher can require an
    exact shared entity without knowing anything vendor-specific.
    """
    signals: list[SignalOccurrence] = []

    matches = (
        db.query(DetectionMatchRecord)
        .filter(DetectionMatchRecord.signal.in_(signal_types))
        .filter(DetectionMatchRecord.timestamp >= since)
        .filter(DetectionMatchRecord.timestamp <= until)
        .all()
    )
    for m in matches:
        signals.append(
            SignalOccurrence(
                signal_type=m.signal, timestamp=m.timestamp, event_id=m.event_id,
                actor_id=m.actor_id, kind="detection", source_id=m.rule_id,
                weight=m.score, label=m.title,
            )
        )

    deviations = (
        db.query(BaselineDeviationRecord)
        .filter(BaselineDeviationRecord.deviation_type.in_(signal_types))
        .filter(BaselineDeviationRecord.timestamp >= since)
        .filter(BaselineDeviationRecord.timestamp <= until)
        .all()
    )
    for d in deviations:
        signals.append(
            SignalOccurrence(
                signal_type=d.deviation_type, timestamp=d.timestamp, event_id=d.event_id,
                actor_id=d.actor_id, kind="deviation", source_id=d.deviation_type,
                weight=d.weight, label=d.reason,
            )
        )

    if entity_field and signals:
        event_ids = {s.event_id for s in signals}
        column = getattr(EventRecord, entity_field)
        entity_by_event = dict(
            db.query(EventRecord.event_id, column).filter(EventRecord.event_id.in_(event_ids)).all()
        )
        for s in signals:
            s.entity = entity_by_event.get(s.event_id)

    signals.sort(key=lambda s: s.timestamp)
    return signals
