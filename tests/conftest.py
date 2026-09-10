"""Point the app at an isolated temp SQLite DB before anything imports it.

Must run before `app.models.db` (and therefore `app.main`) is imported by any
test module, so this lives at the tests/ root and sets the env var at module
import time - conftest.py files are collected before test modules.
"""

import os
import tempfile

import pytest

_tmp_db = tempfile.NamedTemporaryFile(prefix="identitytrace_test_", suffix=".db", delete=False)
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp_db.name}"


@pytest.fixture()
def client():
    """A TestClient backed by a freshly-truncated DB for every test.

    All integration tests share one temp SQLite file for the whole session
    (see module-level setup above); without resetting between tests, a
    match/event created in one test leaks into the next one's assertions.
    """
    from fastapi.testclient import TestClient

    from app.main import app
    from app.models.db import Base, engine

    Base.metadata.drop_all(bind=engine)
    with TestClient(app) as c:
        yield c
