"""Normalized event schema.

This is the common shape every telemetry source (Entra, GitHub, and later
sources) gets translated into. Detections, baselines, and correlation logic
(Phases 2-4) are all written against this schema, not against any one
source's raw format. See docs/architecture.md and blueprint §6.2.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.db import Base

# Sources this project ingests. Kept as a plain tuple (not a hard enum) so a
# new source can be added in Phase 6 without a schema migration for the enum
# type itself - validated in the Pydantic model instead.
KNOWN_SOURCES = ("entra", "github", "m365", "aws", "synthetic")
KNOWN_RESULTS = ("success", "failure", "blocked", "partial")
KNOWN_ACTOR_TYPES = ("user", "service_principal", "app", "token")


class NormalizedEvent(BaseModel):
    """Pydantic model used for validation at the API boundary."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    source: str
    event_type: str
    action: str
    result: str
    actor_id: str
    actor_type: str
    source_actor_id: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    geo_country: Optional[str] = None
    user_agent: Optional[str] = None
    auth_protocol: Optional[str] = None
    mfa_result: Optional[str] = None
    app_id: Optional[str] = None
    # The application's service-principal object ID in the tenant - the one
    # identifier that appeared verbatim on BOTH sides of the real A2
    # admin-consent flow (the requesting user's sign-in and the admin's
    # consent grant). Populated only where the source genuinely carries it
    # (Entra); None otherwise. Nil/empty GUIDs are normalized to None by the
    # normalizer - a placeholder is not a shared entity. Used by
    # entity-bridged correlation rules (app/correlation/), never as a
    # standalone detection field.
    service_principal_id: Optional[str] = None
    permissions: list[str] = Field(default_factory=list)
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    bytes_transferred: Optional[int] = None
    raw_event_ref: Optional[dict[str, Any]] = None

    @field_validator("timestamp")
    @classmethod
    def _ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("source")
    @classmethod
    def _known_source(cls, v: str) -> str:
        if v not in KNOWN_SOURCES:
            raise ValueError(f"source must be one of {KNOWN_SOURCES}, got {v!r}")
        return v

    @field_validator("result")
    @classmethod
    def _known_result(cls, v: str) -> str:
        if v not in KNOWN_RESULTS:
            raise ValueError(f"result must be one of {KNOWN_RESULTS}, got {v!r}")
        return v

    @field_validator("actor_type")
    @classmethod
    def _known_actor_type(cls, v: str) -> str:
        if v not in KNOWN_ACTOR_TYPES:
            raise ValueError(
                f"actor_type must be one of {KNOWN_ACTOR_TYPES}, got {v!r}"
            )
        return v


class EventRecord(Base):
    """SQLAlchemy persistence model mirroring NormalizedEvent."""

    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String, index=True)
    event_type: Mapped[str] = mapped_column(String, index=True)
    action: Mapped[str] = mapped_column(String)
    result: Mapped[str] = mapped_column(String)
    actor_id: Mapped[str] = mapped_column(String, index=True)
    actor_type: Mapped[str] = mapped_column(String)
    source_actor_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    geo_country: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    auth_protocol: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    mfa_result: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    app_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    service_principal_id: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    resource_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    bytes_transferred: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    raw_event_ref: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    def to_schema(self) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            source=self.source,
            event_type=self.event_type,
            action=self.action,
            result=self.result,
            actor_id=self.actor_id,
            actor_type=self.actor_type,
            source_actor_id=self.source_actor_id,
            session_id=self.session_id,
            device_id=self.device_id,
            ip_address=self.ip_address,
            geo_country=self.geo_country,
            user_agent=self.user_agent,
            auth_protocol=self.auth_protocol,
            mfa_result=self.mfa_result,
            app_id=self.app_id,
            service_principal_id=self.service_principal_id,
            permissions=self.permissions or [],
            resource_id=self.resource_id,
            resource_type=self.resource_type,
            bytes_transferred=self.bytes_transferred,
            raw_event_ref=self.raw_event_ref,
        )

    @classmethod
    def from_schema(cls, event: NormalizedEvent) -> "EventRecord":
        return cls(**event.model_dump())
