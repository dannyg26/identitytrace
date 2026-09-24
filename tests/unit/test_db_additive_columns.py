"""create_all() never alters an existing table, so a database created before
events.service_principal_id existed must gain it without losing data."""

from sqlalchemy import create_engine, inspect, text

from app.models import db as db_module


def _columns(engine):
    return {c["name"] for c in inspect(engine).get_columns("events")}


def test_adds_the_missing_column_and_keeps_existing_rows(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE events (event_id VARCHAR PRIMARY KEY, actor_id VARCHAR)"))
        conn.execute(text("INSERT INTO events VALUES ('e1', 'alice')"))
    monkeypatch.setattr(db_module, "engine", engine)

    db_module._add_missing_nullable_columns()

    assert "service_principal_id" in _columns(engine)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT event_id, actor_id, service_principal_id FROM events")).all() == [
            ("e1", "alice", None)
        ]


def test_is_idempotent(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE events (event_id VARCHAR PRIMARY KEY)"))
    monkeypatch.setattr(db_module, "engine", engine)

    db_module._add_missing_nullable_columns()
    db_module._add_missing_nullable_columns()  # must not raise "duplicate column"

    assert "service_principal_id" in _columns(engine)


def test_does_nothing_when_the_table_does_not_exist_yet(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")
    monkeypatch.setattr(db_module, "engine", engine)

    db_module._add_missing_nullable_columns()  # create_all will make the table later

    assert not inspect(engine).has_table("events")
