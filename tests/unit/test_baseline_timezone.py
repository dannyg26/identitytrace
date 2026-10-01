from datetime import datetime, timedelta, timezone

from app.baselines.profile import IdentityProfile, extend_profile
from app.models.event import NormalizedEvent


def test_profile_uses_utc_when_postgres_returns_local_offset():
    event = NormalizedEvent(event_id="timezone", timestamp="2026-01-01T08:00:00Z", source="entra",
                            actor_id="alice", actor_type="user", event_type="signin", action="login", result="success")
    # ORM timestamps can use the PostgreSQL session timezone, bypassing model validation.
    record = event.model_copy(update={"timestamp": datetime(2026, 1, 1, 3, tzinfo=timezone(timedelta(hours=-5)))})
    fresh, rebuilt = IdentityProfile(actor_id="alice"), IdentityProfile(actor_id="alice")
    extend_profile(fresh, event)
    extend_profile(rebuilt, record)
    assert rebuilt.login_hours == {8}
    assert fresh.model_dump(mode="json") == rebuilt.model_dump(mode="json")
