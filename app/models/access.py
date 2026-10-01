"""Deployment binding and hashed, short-lived browser sessions."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.db import Base


class DeploymentBinding(Base):
    __tablename__ = "deployment_binding"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[str] = mapped_column(String, nullable=False)


class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    token_hash: Mapped[str] = mapped_column(String, primary_key=True)
    principal: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String)
    organization_id: Mapped[str] = mapped_column(String)
    issuer: Mapped[str] = mapped_column(String)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
