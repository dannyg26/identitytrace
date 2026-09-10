"""Database engine/session setup.

Defaults to a local SQLite file so the project runs with zero external
services. Set DATABASE_URL to a Postgres DSN (see docker-compose.yml) to
switch - no code changes required.
"""

from __future__ import annotations

import os
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def _database_url() -> str:
    return os.environ.get("DATABASE_URL", "sqlite:///./identitytrace.db")


DATABASE_URL = _database_url()

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    """Create tables if they don't exist yet.

    Fine for SQLite dev use and for this project's current stage. A real
    deployment (Phase 8 hardening) should use migrations instead.
    """
    from app.models import (  # noqa: F401  (register ORM models on Base)
        baseline,
        detection,
        event,
        incident,
    )

    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
