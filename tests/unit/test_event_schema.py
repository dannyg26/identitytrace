from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models.event import NormalizedEvent


def _base_kwargs(**overrides):
    kwargs = dict(
        timestamp=datetime(2026, 9, 9, 17, 2, 11, tzinfo=timezone.utc),
        source="entra",
        event_type="signin",
        action="login",
        result="success",
        actor_id="alice@example.test",
        actor_type="user",
    )
    kwargs.update(overrides)
    return kwargs


def test_minimal_valid_event_gets_a_generated_id():
    event = NormalizedEvent(**_base_kwargs())
    assert event.event_id  # generated
    assert event.permissions == []
    assert event.raw_event_ref is None


def test_naive_timestamp_is_assumed_utc():
    naive = datetime(2026, 9, 9, 17, 2, 11)
    event = NormalizedEvent(**_base_kwargs(timestamp=naive))
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset().total_seconds() == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "not_a_real_source"),
        ("result", "maybe"),
        ("actor_type", "robot"),
    ],
)
def test_unknown_enum_like_values_are_rejected(field, value):
    with pytest.raises(ValidationError):
        NormalizedEvent(**_base_kwargs(**{field: value}))


def test_missing_required_field_is_rejected():
    kwargs = _base_kwargs()
    del kwargs["actor_id"]
    with pytest.raises(ValidationError):
        NormalizedEvent(**kwargs)


def test_permissions_and_raw_event_ref_round_trip():
    event = NormalizedEvent(
        **_base_kwargs(
            event_type="oauth_consent",
            action="grant_permission",
            permissions=["offline_access", "Files.Read.All"],
            raw_event_ref={"id": "evt-1", "note": "source payload"},
        )
    )
    assert event.permissions == ["offline_access", "Files.Read.All"]
    assert event.raw_event_ref == {"id": "evt-1", "note": "source payload"}
