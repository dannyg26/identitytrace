"""Database engine/session setup.

Defaults to a local SQLite file so the project runs with zero external
services. Set DATABASE_URL to a Postgres DSN (see docker-compose.yml) to
switch - no code changes required.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import URL, Column, Integer, String, Table, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


Table("identitytrace_schema_versions", Base.metadata,
      Column("version", Integer, primary_key=True), Column("applied_at", String, nullable=False))


def _database_url() -> str:
    if os.environ.get("IDENTITYTRACE_DB_HOST"):
        secret_file = os.environ.get("IDENTITYTRACE_DB_PASSWORD_FILE")
        password = Path(secret_file).read_text(encoding="utf-8").strip() if secret_file else os.environ["IDENTITYTRACE_DB_PASSWORD"]
        return URL.create("postgresql+psycopg", username="identitytrace",
                          password=password,
                          host=os.environ["IDENTITYTRACE_DB_HOST"], database="identitytrace").render_as_string(hide_password=False)
    return os.environ.get("DATABASE_URL", "sqlite:///./identitytrace.db")


DATABASE_URL = _database_url()

_connect_args = {"check_same_thread": False, "timeout": 30} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    """Create tables if they don't exist yet.

    Fine for SQLite dev use and for this project's current stage. A real
    deployment (Phase 8 hardening) should use migrations instead.
    """
    from app.models import (  # noqa: F401  (register ORM models on Base)
        access,
        baseline,
        detection,
        event,
        incident,
        operations,
    )

    _check_schema_version()
    Base.metadata.create_all(bind=engine)
    _run_migrations()


SCHEMA_VERSION = 3


def verify_schema(organization_id=None):
    """Check a pre-migrated production database without modifying it."""
    with engine.connect() as connection:
        current = connection.execute(text("SELECT MAX(version) FROM identitytrace_schema_versions")).scalar()
    if current != SCHEMA_VERSION:
        raise RuntimeError("Run scripts/migrate_database.py before starting this application version")
    if organization_id:
        with engine.connect() as connection:
            bound = connection.execute(text("SELECT organization_id FROM deployment_binding WHERE id=1")).scalar()
        if bound != organization_id:
            raise RuntimeError("Database belongs to a different organization or has not been bound")


def bind_organization(organization_id):
    """Explicit administrative operation. An existing database cannot be reassigned."""
    if not organization_id or len(organization_id) > 320:
        raise ValueError("Provide a nonempty organization identifier of at most 320 characters")
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.execute(text("SELECT pg_advisory_xact_lock(194827362)"))
        bound = connection.execute(text("SELECT organization_id FROM deployment_binding WHERE id=1")).scalar()
        if bound and bound != organization_id:
            raise RuntimeError("Refusing to reassign a database to another organization")
        if not bound:
            connection.execute(text("INSERT INTO deployment_binding (id, organization_id) VALUES (1, :org)"), {"org": organization_id})


def _check_schema_version():
    if inspect(engine).has_table("identitytrace_schema_versions"):
        with engine.connect() as connection:
            version = connection.execute(text("SELECT MAX(version) FROM identitytrace_schema_versions")).scalar() or 0
        if version > SCHEMA_VERSION:
            raise RuntimeError("Database schema is newer than this application; refusing to downgrade")


def _run_migrations():
    """Forward-only, repeatable upgrades. Back up before upgrading a live DB."""
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE IF NOT EXISTS identitytrace_schema_versions (version INTEGER PRIMARY KEY, applied_at VARCHAR NOT NULL)"))
        applied = set(connection.execute(text("SELECT version FROM identitytrace_schema_versions")).scalars())
    if 1 not in applied:
        _add_missing_nullable_columns()
        with engine.begin() as connection:
            connection.execute(text("INSERT INTO identitytrace_schema_versions VALUES (1, :time)"),
                               {"time": datetime.now(timezone.utc).isoformat()})
    if 2 not in applied:
        with engine.begin() as connection:
            for name, table, columns in (
                ("ix_events_actor_time", "events", "actor_id, timestamp"),
                ("ix_matches_actor_time", "detection_matches", "actor_id, timestamp"),
                ("ix_deviations_actor_time", "baseline_deviations", "actor_id, timestamp"),
            ):
                connection.execute(text(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({columns})"))
            connection.execute(text("INSERT INTO identitytrace_schema_versions VALUES (2, :time)"),
                               {"time": datetime.now(timezone.utc).isoformat()})
    if 3 not in applied:
        # create_all above creates the additive access/session tables first.
        with engine.begin() as connection:
            connection.execute(text("INSERT INTO identitytrace_schema_versions VALUES (3, :time)"),
                               {"time": datetime.now(timezone.utc).isoformat()})


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
    ("events", "source_actor_id", "VARCHAR"),
    ("incidents", "superseded_at", "TIMESTAMP"),
    ("incidents", "superseded_reason", "VARCHAR"),
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
