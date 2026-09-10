from datetime import datetime, timezone

from app.baselines.deviation import (
    MIN_HISTORY_FOR_BASELINE,
    VOLUME_ANOMALY_MULTIPLIER,
    evaluate_deviations,
)
from app.baselines.profile import IdentityProfile
from app.models.event import NormalizedEvent


def _event(**overrides) -> NormalizedEvent:
    kwargs = dict(
        timestamp=datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc),
        source="entra",
        event_type="signin",
        action="login",
        result="success",
        actor_id="alice@example.test",
        actor_type="user",
    )
    kwargs.update(overrides)
    return NormalizedEvent(**kwargs)


def _established_profile(**overrides) -> IdentityProfile:
    kwargs = dict(
        actor_id="alice@example.test",
        event_count=MIN_HISTORY_FOR_BASELINE + 5,
        known_devices={"d1"},
        known_ips={"1.1.1.1"},
        known_countries={"US"},
        known_apps={"app-1"},
        known_auth_protocols={"interactive"},
        login_hours={9, 10, 11},
        max_bytes_transferred=1000,
    )
    kwargs.update(overrides)
    return IdentityProfile(**kwargs)


def test_thin_profile_flags_nothing():
    profile = IdentityProfile(actor_id="alice@example.test", event_count=MIN_HISTORY_FOR_BASELINE - 1)
    event = _event(device_id="brand-new-device")
    assert evaluate_deviations(event, profile) == []


def test_known_values_do_not_deviate():
    profile = _established_profile()
    event = _event(
        device_id="d1", ip_address="1.1.1.1", geo_country="US",
        app_id="app-1", auth_protocol="interactive", timestamp=datetime(2026, 9, 9, 9, 0, tzinfo=timezone.utc),
    )
    assert evaluate_deviations(event, profile) == []


def test_new_device_flagged():
    profile = _established_profile()
    event = _event(device_id="new-device")
    types = {d.deviation_type for d in evaluate_deviations(event, profile)}
    assert "new_device" in types


def test_new_ip_flagged():
    profile = _established_profile()
    event = _event(ip_address="9.9.9.9")
    types = {d.deviation_type for d in evaluate_deviations(event, profile)}
    assert "new_ip" in types


def test_new_country_flagged():
    profile = _established_profile()
    event = _event(geo_country="RU")
    types = {d.deviation_type for d in evaluate_deviations(event, profile)}
    assert "new_country" in types


def test_new_app_flagged():
    profile = _established_profile()
    event = _event(app_id="app-unseen")
    types = {d.deviation_type for d in evaluate_deviations(event, profile)}
    assert "new_app" in types


def test_new_auth_protocol_flagged():
    profile = _established_profile()
    event = _event(auth_protocol="deviceCode")
    types = {d.deviation_type for d in evaluate_deviations(event, profile)}
    assert "new_auth_protocol" in types


def test_unusual_login_hour_flagged():
    profile = _established_profile()
    event = _event(timestamp=datetime(2026, 9, 9, 3, 0, tzinfo=timezone.utc))  # 3am, never seen
    types = {d.deviation_type for d in evaluate_deviations(event, profile)}
    assert "unusual_login_hour" in types


def test_usual_login_hour_not_flagged():
    profile = _established_profile()
    event = _event(timestamp=datetime(2026, 9, 9, 10, 0, tzinfo=timezone.utc))
    types = {d.deviation_type for d in evaluate_deviations(event, profile)}
    assert "unusual_login_hour" not in types


def test_volume_anomaly_flagged_above_multiplier():
    profile = _established_profile(max_bytes_transferred=1000)
    event = _event(bytes_transferred=1000 * VOLUME_ANOMALY_MULTIPLIER + 1)
    types = {d.deviation_type for d in evaluate_deviations(event, profile)}
    assert "volume_anomaly" in types


def test_volume_within_normal_range_not_flagged():
    profile = _established_profile(max_bytes_transferred=1000)
    event = _event(bytes_transferred=1500)
    types = {d.deviation_type for d in evaluate_deviations(event, profile)}
    assert "volume_anomaly" not in types


def test_missing_fields_are_not_flagged_as_deviations():
    profile = _established_profile()
    # no device_id/ip_address/app_id/bytes_transferred set, and an hour
    # that's within the established baseline so nothing else fires either.
    event = _event(timestamp=datetime(2026, 9, 9, 9, 0, tzinfo=timezone.utc))
    assert evaluate_deviations(event, profile) == []


def test_every_deviation_has_a_human_readable_reason():
    profile = _established_profile()
    event = _event(device_id="new-device", ip_address="9.9.9.9")
    deviations = evaluate_deviations(event, profile)
    assert len(deviations) >= 2
    for d in deviations:
        assert d.reason and isinstance(d.reason, str)
        assert d.weight > 0
