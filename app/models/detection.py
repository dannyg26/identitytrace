"""Persistence for detection matches (a rule firing against an event).

Kept separate from app/detections/schema.py (the rule definition) and
app/detections/engine.py (the pure evaluator) - this module only knows how
to store/query the *results* of evaluation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.detections.engine import DetectionMatch
from app.models.db import Base


class DetectionMatchRecord(Base):
    __tablename__ = "detection_matches"

    match_id: Mapped[str] = mapped_column(String, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String, index=True)
    event_id: Mapped[str] = mapped_column(
        String, ForeignKey("events.event_id"), index=True
    )
    actor_id: Mapped[str] = mapped_column(String, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    title: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String, index=True)
    score: Mapped[int] = mapped_column(Integer)
    scenario: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    signal: Mapped[str] = mapped_column(String, index=True)
    attack: Mapped[list] = mapped_column(JSON, default=list)
    reasons: Mapped[list] = mapped_column(JSON, default=list)

    @classmethod
    def from_match(cls, match: DetectionMatch) -> "DetectionMatchRecord":
        data = match.to_dict()
        # Deterministic on (event_id, rule_id) so replaying the same event
        # (blueprint's "events can be ingested, queried, replayed") merges
        # back into the same match row instead of duplicating it.
        match_id = f"{data['event_id']}:{data['rule_id']}"
        return cls(
            match_id=match_id,
            rule_id=data["rule_id"],
            event_id=data["event_id"],
            actor_id=data["actor_id"],
            timestamp=data["timestamp"],
            title=data["title"],
            severity=data["severity"],
            score=data["score"],
            scenario=data["scenario"],
            signal=data["signal"],
            attack=data["attack"],
            reasons=data["reasons"],
        )

    def to_dict(self) -> dict:
        return {
            "match_id": self.match_id,
            "rule_id": self.rule_id,
            "event_id": self.event_id,
            "actor_id": self.actor_id,
            "timestamp": self.timestamp,
            "title": self.title,
            "severity": self.severity,
            "score": self.score,
            "scenario": self.scenario,
            "signal": self.signal,
            "attack": self.attack,
            "reasons": self.reasons,
        }
