"""Detection library and match query API.

- GET /detections    - the loaded rule library (blueprint §9.2/§9.1 "Detection library").
- GET /matches       - every detection match, filterable/paginated.
- GET /matches/{id}  - a single match.
- GET /alerts        - Phase 9 #9: high/critical-severity matches as their
  own actionable queue - a standalone atomic signal (e.g. A6's bulk
  transfer, with no correlation rule by design - see
  docs/evaluation.md) is still analyst-actionable on its own. Not a
  replacement for /matches (which stays the complete record) or
  /incidents (correlated, multi-signal evidence) - a third, narrower view
  for "what, by itself, is already worth a look."

Rules are loaded once at startup (see app/main.py) and passed in via a small
module-level registry rather than re-reading YAML on every request - rule
changes require a restart for now, consistent with "no undocumented logic
changes in the UI" (blueprint §12.2).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.detections.schema import DetectionRule
from app.models.db import get_db
from app.models.detection import DetectionMatchRecord

router = APIRouter(tags=["detections"])

_loaded_rules: list[DetectionRule] = []


def set_loaded_rules(rules: list[DetectionRule]) -> None:
    global _loaded_rules
    _loaded_rules = rules


def get_loaded_rules() -> list[DetectionRule]:
    return _loaded_rules


@router.get("/detections")
def list_detections(db: Session = Depends(get_db)) -> list[dict]:
    last_triggered = dict(
        db.query(
            DetectionMatchRecord.rule_id, func.max(DetectionMatchRecord.timestamp)
        ).group_by(DetectionMatchRecord.rule_id)
    )
    return [
        {
            "id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "severity": rule.severity.value,
            "version": rule.version,
            "enabled": rule.enabled,
            "source": rule.source,
            "event_type": rule.event_type,
            "score": rule.score,
            "scenario": rule.scenario,
            "attack": [a.model_dump() for a in rule.attack],
            "last_triggered": last_triggered.get(rule.id),
        }
        for rule in sorted(_loaded_rules, key=lambda r: r.id)
    ]


@router.get("/matches")
def list_matches(
    rule_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    severity: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> list[dict]:
    limit = max(1, min(limit, 1000))
    query = db.query(DetectionMatchRecord)
    if rule_id:
        query = query.filter(DetectionMatchRecord.rule_id == rule_id)
    if actor_id:
        query = query.filter(DetectionMatchRecord.actor_id == actor_id)
    if severity:
        query = query.filter(DetectionMatchRecord.severity == severity)
    if since:
        query = query.filter(DetectionMatchRecord.timestamp >= since)
    if until:
        query = query.filter(DetectionMatchRecord.timestamp <= until)
    records = (
        query.order_by(DetectionMatchRecord.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [r.to_dict() for r in records]


@router.get("/matches/{match_id}")
def get_match(match_id: str, db: Session = Depends(get_db)) -> dict:
    record = db.get(DetectionMatchRecord, match_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"match '{match_id}' not found")
    return record.to_dict()


@router.get("/alerts")
def list_alerts(
    actor_id: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> list[dict]:
    """High/critical-severity atomic matches - standalone signals worth an
    analyst's attention on their own, independent of whether a
    correlation rule ever chains them into an incident."""
    limit = max(1, min(limit, 1000))
    query = db.query(DetectionMatchRecord).filter(
        DetectionMatchRecord.severity.in_(["high", "critical"])
    )
    if actor_id:
        query = query.filter(DetectionMatchRecord.actor_id == actor_id)
    if since:
        query = query.filter(DetectionMatchRecord.timestamp >= since)
    if until:
        query = query.filter(DetectionMatchRecord.timestamp <= until)
    records = (
        query.order_by(DetectionMatchRecord.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [r.to_dict() for r in records]
