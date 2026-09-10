"""Behavioral baselines (blueprint L2): a per-identity "normal" profile
built from prior events, used to flag deviations at ingestion time (see
app/baselines/deviation.py).

Deliberately computed by querying history rather than incrementally
maintained as separate mutable state - the simplest correct thing at this
project's scale (SQLite/Postgres, thousands of events), and it avoids a
second source of truth that could drift out of sync with the events table.
A materialized/cached profile would be a reasonable optimization later if
ingestion volume ever made this query the bottleneck - not needed yet.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.models.event import EventRecord


class IdentityProfile(BaseModel):
    actor_id: str
    event_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    known_devices: set[str] = Field(default_factory=set)
    known_ips: set[str] = Field(default_factory=set)
    known_countries: set[str] = Field(default_factory=set)
    known_apps: set[str] = Field(default_factory=set)
    known_resources: set[str] = Field(default_factory=set)
    known_auth_protocols: set[str] = Field(default_factory=set)
    login_hours: set[int] = Field(default_factory=set)  # UTC hours (0-23) seen
    max_bytes_transferred: Optional[int] = None
    avg_bytes_transferred: Optional[float] = None


def build_profile(
    db: Session, actor_id: str, before: Optional[datetime] = None
) -> IdentityProfile:
    """Build actor_id's profile from events strictly before `before`.

    `before` should be the timestamp of the event you're about to evaluate,
    so the profile only reflects what was already known about the identity
    at that point in time - not the event itself, and not later events
    (which would leak future information into a deviation check).
    """
    query = db.query(EventRecord).filter(EventRecord.actor_id == actor_id)
    if before is not None:
        query = query.filter(EventRecord.timestamp < before)
    records = query.all()

    profile = IdentityProfile(actor_id=actor_id, event_count=len(records))
    if not records:
        return profile

    timestamps = [r.timestamp for r in records]
    profile.first_seen = min(timestamps)
    profile.last_seen = max(timestamps)

    transferred: list[int] = []
    for r in records:
        if r.device_id:
            profile.known_devices.add(r.device_id)
        if r.ip_address:
            profile.known_ips.add(r.ip_address)
        if r.geo_country:
            profile.known_countries.add(r.geo_country)
        if r.app_id:
            profile.known_apps.add(r.app_id)
        if r.resource_id:
            profile.known_resources.add(r.resource_id)
        if r.auth_protocol:
            profile.known_auth_protocols.add(r.auth_protocol)
        profile.login_hours.add(r.timestamp.hour)
        if r.bytes_transferred is not None:
            transferred.append(r.bytes_transferred)

    if transferred:
        profile.max_bytes_transferred = max(transferred)
        profile.avg_bytes_transferred = sum(transferred) / len(transferred)

    return profile
