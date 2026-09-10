"""Unify Phase 2 detection matches and Phase 3 baseline deviations into one
stream of "signals" - the vocabulary correlation sequences are written
against (a detection rule's `signal` tag, or a deviation's `deviation_type`
verbatim - e.g. "new_device" is already a signal name, no tagging needed).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.baseline import BaselineDeviationRecord
from app.models.detection import DetectionMatchRecord


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
