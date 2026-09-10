"""Identity profile API (blueprint §9.2: GET /identities/{id} - baseline,
recent events, sessions, risk).

`load_identity_context` is shared with the dashboard (app/main.py) so the
API and the HTML page never compute the profile two different ways.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.baselines.profile import build_profile
from app.models.baseline import BaselineDeviationRecord
from app.models.db import get_db
from app.models.detection import DetectionMatchRecord
from app.models.event import EventRecord
from app.models.incident import IncidentRecord

router = APIRouter(tags=["identities"])

_SET_FIELDS = (
    "known_devices",
    "known_ips",
    "known_countries",
    "known_apps",
    "known_resources",
    "known_auth_protocols",
    "login_hours",
)


def load_identity_context(db: Session, actor_id: str, recent_limit: int = 20) -> Optional[dict]:
    """Everything the identity profile view needs, or None if unknown."""
    profile = build_profile(db, actor_id)
    if profile.event_count == 0:
        return None

    profile_dict = profile.model_dump()
    for field in _SET_FIELDS:
        profile_dict[field] = sorted(profile_dict[field])

    recent_events = (
        db.query(EventRecord)
        .filter(EventRecord.actor_id == actor_id)
        .order_by(EventRecord.timestamp.desc())
        .limit(recent_limit)
        .all()
    )
    recent_deviations = (
        db.query(BaselineDeviationRecord)
        .filter(BaselineDeviationRecord.actor_id == actor_id)
        .order_by(BaselineDeviationRecord.timestamp.desc())
        .limit(recent_limit)
        .all()
    )
    recent_matches = (
        db.query(DetectionMatchRecord)
        .filter(DetectionMatchRecord.actor_id == actor_id)
        .order_by(DetectionMatchRecord.timestamp.desc())
        .limit(recent_limit)
        .all()
    )
    # Sessions aren't a modeled entity yet (that's Phase 5's identity
    # graph) - approximate with the distinct session_ids seen recently.
    recent_sessions = sorted(
        {e.session_id for e in recent_events if e.session_id}, reverse=True
    )
    prior_incidents = (
        db.query(IncidentRecord)
        .filter(IncidentRecord.identity_id == actor_id)
        .order_by(IncidentRecord.last_event_at.desc())
        .limit(recent_limit)
        .all()
    )

    return {
        "actor_id": actor_id,
        "profile": profile_dict,
        "recent_events": [r.to_schema() for r in recent_events],
        "recent_deviations": [d.to_dict() for d in recent_deviations],
        "recent_matches": [m.to_dict() for m in recent_matches],
        "recent_sessions": recent_sessions,
        "prior_incidents": [i.to_dict() for i in prior_incidents],
    }


@router.get("/identities")
def list_identities(db: Session = Depends(get_db)) -> list[dict]:
    rows = (
        db.query(
            EventRecord.actor_id,
            func.count(EventRecord.event_id),
            func.min(EventRecord.timestamp),
            func.max(EventRecord.timestamp),
        )
        .group_by(EventRecord.actor_id)
        .order_by(func.max(EventRecord.timestamp).desc())
        .all()
    )
    return [
        {
            "actor_id": actor_id,
            "event_count": count,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
        for actor_id, count, first_seen, last_seen in rows
    ]


@router.get("/identities/{actor_id}")
def get_identity(actor_id: str, db: Session = Depends(get_db)) -> dict:
    context = load_identity_context(db, actor_id)
    if context is None:
        raise HTTPException(status_code=404, detail=f"identity '{actor_id}' not found")
    return context
