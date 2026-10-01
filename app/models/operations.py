"""Derived baseline checkpoints, explicit identity links, and analyst audit records."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.db import Base


class IdentityLink(Base):
    __tablename__ = "identity_links"
    source: Mapped[str] = mapped_column(String, primary_key=True)
    alias: Mapped[str] = mapped_column(String, primary_key=True)
    canonical_id: Mapped[str] = mapped_column(String, index=True)


class BaselineState(Base):
    __tablename__ = "baseline_states"
    actor_id: Mapped[str] = mapped_column(String, primary_key=True)
    last_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    profile: Mapped[dict] = mapped_column(JSON)


class AuditRecord(Base):
    __tablename__ = "audit_records"
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    principal: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String, index=True)
    entity_id: Mapped[str] = mapped_column(String)
    before: Mapped[dict] = mapped_column(JSON, default=dict)
    after: Mapped[dict] = mapped_column(JSON, default=dict)

    def to_dict(self):
        return {key: getattr(self, key) for key in (
            "id", "timestamp", "principal", "action", "entity_id", "before", "after"
        )}
