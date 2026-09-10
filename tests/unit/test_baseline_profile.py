from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.baselines.profile import build_profile
from app.models.db import Base
from app.models.event import EventRecord, NormalizedEvent


@pytest.fixture()
def db():
    # An isolated in-memory DB per test - independent of the app's own
    # engine/session (and of tests/conftest.py's shared temp-file DB), so
    # these are pure unit tests of build_profile's query logic.
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session = Session(engine)
    yield session
    session.close()


def _insert(db, **overrides):
    kwargs = dict(
        timestamp=datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc),
        source="entra",
        event_type="signin",
        action="login",
        result="success",
        actor_id="alice@example.test",
        actor_type="user",
    )
    kwargs.update(overrides)
    event = NormalizedEvent(**kwargs)
    db.add(EventRecord.from_schema(event))
    db.commit()
    return event


def test_empty_profile_for_unknown_actor(db):
    profile = build_profile(db, "nobody@example.test")
    assert profile.event_count == 0
    assert profile.known_devices == set()
    assert profile.first_seen is None


def test_profile_accumulates_known_values(db):
    _insert(db, device_id="d1", ip_address="1.1.1.1", geo_country="US", app_id="app-1")
    _insert(db, device_id="d2", ip_address="2.2.2.2", geo_country="US", app_id="app-2",
            timestamp=datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc))

    profile = build_profile(db, "alice@example.test")
    assert profile.event_count == 2
    assert profile.known_devices == {"d1", "d2"}
    assert profile.known_ips == {"1.1.1.1", "2.2.2.2"}
    assert profile.known_countries == {"US"}
    assert profile.known_apps == {"app-1", "app-2"}


def test_profile_is_scoped_to_actor_id(db):
    _insert(db, actor_id="alice@example.test", device_id="d1")
    _insert(db, actor_id="bob@example.test", device_id="d2")

    profile = build_profile(db, "alice@example.test")
    assert profile.event_count == 1
    assert profile.known_devices == {"d1"}


def test_before_excludes_events_at_or_after_that_timestamp(db):
    t1 = datetime(2026, 9, 1, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 2, tzinfo=timezone.utc)
    t3 = datetime(2026, 9, 3, tzinfo=timezone.utc)
    _insert(db, timestamp=t1, device_id="d1")
    _insert(db, timestamp=t2, device_id="d2")

    # before t2: only the t1 event is in scope
    profile = build_profile(db, "alice@example.test", before=t2)
    assert profile.event_count == 1
    assert profile.known_devices == {"d1"}

    # before t3: both are in scope
    profile = build_profile(db, "alice@example.test", before=t3)
    assert profile.event_count == 2
    assert profile.known_devices == {"d1", "d2"}


def test_volume_stats(db):
    _insert(db, bytes_transferred=100)
    _insert(db, bytes_transferred=300, timestamp=datetime(2026, 9, 2, tzinfo=timezone.utc))

    profile = build_profile(db, "alice@example.test")
    assert profile.max_bytes_transferred == 300
    assert profile.avg_bytes_transferred == 200


def test_login_hours_collected(db):
    _insert(db, timestamp=datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc))
    _insert(db, timestamp=datetime(2026, 9, 2, 17, 0, tzinfo=timezone.utc))

    profile = build_profile(db, "alice@example.test")
    assert profile.login_hours == {9, 17}
