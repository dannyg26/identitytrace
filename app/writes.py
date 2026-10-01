"""Serialize ingestion/reconciliation across threads and database connections."""

from contextlib import contextmanager
from threading import RLock

from sqlalchemy import text

_lock = RLock()


@contextmanager
def write_lock(db):
    with _lock:
        connection = db.connection()
        if connection.dialect.name == "postgresql":
            connection.execute(text("SELECT pg_advisory_xact_lock(194827361)"))
        elif connection.dialect.name == "sqlite":
            if not connection.connection.driver_connection.in_transaction:
                connection.exec_driver_sql("BEGIN IMMEDIATE")
        yield
