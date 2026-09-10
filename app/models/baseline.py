"""Persistence for baseline deviations (a deviation flagged against an
event). Mirrors app/models/detection.py's split between rule evaluation and
match storage - app/baselines/deviation.py stays a pure function, this
module only knows how to store/query its results.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.baselines.deviation import Deviation
from app.models.db import Base
from app.models.event import NormalizedEvent


class BaselineDeviationRecord(Base):
    __tablename__ = "baseline_deviations"

    deviation_id: Mapped[str] = mapped_column(String, primary_key=True)
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("events.event_id"), index=True
    )
    actor_id: Mapped[str] = mapped_column(String, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    deviation_type: Mapped[str] = mapped_column(String, index=True)
    field: Mapped[str] = mapped_column(String)
    weight: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(String)

    @classmethod
    def from_deviation(
        cls, event: NormalizedEvent, deviation: Deviation
    ) -> "BaselineDeviationRecord":
        # Deterministic on (event_id, deviation_type) so replaying the same
        # event merges back into the same row instead of duplicating it -
        # same replay-safety rule as DetectionMatchRecord.
        return cls(
            deviation_id=f"{event.event_id}:{deviation.deviation_type}",
            event_id=event.event_id,
            actor_id=event.actor_id,
            timestamp=event.timestamp,
            deviation_type=deviation.deviation_type,
            field=deviation.field,
            weight=deviation.weight,
            reason=deviation.reason,
        )

    def to_dict(self) -> dict:
        return {
            "deviation_id": self.deviation_id,
            "event_id": self.event_id,
            "actor_id": self.actor_id,
            "timestamp": self.timestamp,
            "deviation_type": self.deviation_type,
            "field": self.field,
            "weight": self.weight,
            "reason": self.reason,
        }
