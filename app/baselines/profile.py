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

from datetime import datetime, timezone
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
    transfer_count: int = 0


def extend_profile(profile: IdentityProfile, event) -> None:
    """Fold one event into a checkpoint in constant work, excluding set growth."""
    timestamp = event.timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.astimezone(timezone.utc)
    profile.event_count += 1
    profile.first_seen = min(profile.first_seen, timestamp) if profile.first_seen else timestamp
    profile.last_seen = max(profile.last_seen, timestamp) if profile.last_seen else timestamp
    for field, collection in (
        ("device_id", "known_devices"), ("ip_address", "known_ips"),
        ("geo_country", "known_countries"), ("app_id", "known_apps"),
        ("resource_id", "known_resources"), ("auth_protocol", "known_auth_protocols"),
    ):
        value = getattr(event, field)
        if value:
            getattr(profile, collection).add(value)
    profile.login_hours.add(timestamp.hour)
    if event.bytes_transferred is not None:
        count = profile.transfer_count
        profile.avg_bytes_transferred = (
            (profile.avg_bytes_transferred or 0) * count + event.bytes_transferred
        ) / (count + 1)
        profile.transfer_count += 1
        profile.max_bytes_transferred = max(
            profile.max_bytes_transferred if profile.max_bytes_transferred is not None else event.bytes_transferred,
            event.bytes_transferred,
        )


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

    profile = IdentityProfile(actor_id=actor_id)
    for r in records:
        extend_profile(profile, r)
    return profile
