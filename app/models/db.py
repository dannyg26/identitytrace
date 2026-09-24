"""Database engine/session setup.

Defaults to a local SQLite file so the project runs with zero external
services. Set DATABASE_URL to a Postgres DSN (see docker-compose.yml) to
switch - no code changes required.
"""

from __future__ import annotations

import os
from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
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
    _add_missing_nullable_columns()


# create_all() creates missing *tables* but never alters an existing one, so
# a column added to a model after a dev database was first created would
# raise "no such column" on the next query. These are additive, nullable,
# derived-data columns only - a full migration tool remains a Phase 8
# concern - so a plain idempotent ADD COLUMN is enough (valid on both
# SQLite and Postgres).
_ADDITIVE_COLUMNS: list[tuple[str, str, str]] = [
    ("events", "service_principal_id", "VARCHAR"),
    ("incidents", "classification", "VARCHAR"),
    ("incidents", "escalation", "JSON"),
]


def _add_missing_nullable_columns() -> None:
    inspector = inspect(engine)
    for table, column, ddl_type in _ADDITIVE_COLUMNS:
        if not inspector.has_table(table):
            continue
        existing = {c["name"] for c in inspector.get_columns(table)}
        if column in existing:
            continue
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
