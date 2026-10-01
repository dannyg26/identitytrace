"""One filter definition shared by the queue, API and downloadable reports."""

from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import or_

from app.models.incident import IncidentRecord


class IncidentFilters(BaseModel):
    q: str = Field(default="", max_length=200)
    severity: str | None = None
    status: str | None = None
    identity_id: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    include_superseded: bool = False

    @field_validator("since", "until")
    @classmethod
    def utc_dates(cls, value):
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


def incident_query(db, filters):
    if filters.since and filters.until and filters.since > filters.until:
        raise HTTPException(422, "since must precede until")
    query = db.query(IncidentRecord)
    if not filters.include_superseded:
        query = query.filter(IncidentRecord.superseded_at.is_(None))
    for name in ("severity", "status", "identity_id"):
        if value := getattr(filters, name):
            query = query.filter(getattr(IncidentRecord, name) == value)
    if filters.q:
        query = query.filter(or_(*[column.icontains(filters.q, autoescape=True) for column in (
            IncidentRecord.incident_id, IncidentRecord.identity_id,
            IncidentRecord.correlation_rule_title, IncidentRecord.notes)]))
    if filters.since:
        query = query.filter(IncidentRecord.last_event_at >= filters.since)
    if filters.until:
        query = query.filter(IncidentRecord.last_event_at <= filters.until)
    return query.order_by(IncidentRecord.last_event_at.desc(), IncidentRecord.incident_id)
