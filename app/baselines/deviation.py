"""Deviation flags: compare one event against an identity's prior baseline
profile (blueprint L2, §7.1's baseline feature list).

Each deviation type carries a fixed weight - the contribution it would make
to `behavioral_deviation` in the blueprint's incident-score formula (§7.2).
Nothing sums these into an incident score yet; that's Phase 4 correlation's
job. This module only decides, per event, "is this different from what
we've seen for this identity before, and why."
"""

from __future__ import annotations

from dataclasses import dataclass

from app.baselines.profile import IdentityProfile
from app.models.event import NormalizedEvent

# Below this many prior events, an identity's profile is too thin to call
# anything "new" - everything looks new on day one. Avoids flooding a
# freshly-seen identity with low-value noise.
MIN_HISTORY_FOR_BASELINE = 3

# An event moving more than this multiple of the identity's prior max is
# flagged as a volume anomaly rather than normal variance.
VOLUME_ANOMALY_MULTIPLIER = 3


# Every deviation_type evaluate_deviations can emit. Correlation rules that
# reference a deviation as escalation evidence are validated against this, so
# a rule can never depend on a signal the deviation layer does not produce.
DEVIATION_TYPES = frozenset(
    {
        "new_device",
        "new_ip",
        "new_country",
        "new_app",
        "new_auth_protocol",
        "unusual_login_hour",
        "volume_anomaly",
    }
)


@dataclass
class Deviation:
    deviation_type: str
    field: str
    weight: int
    reason: str


def evaluate_deviations(event: NormalizedEvent, profile: IdentityProfile) -> list[Deviation]:
    if profile.event_count < MIN_HISTORY_FOR_BASELINE:
        return []

    deviations: list[Deviation] = []

    if event.device_id and event.device_id not in profile.known_devices:
        deviations.append(
            Deviation(
                "new_device",
                "device_id",
                15,
                f"device_id {event.device_id!r} not seen before for this identity "
                f"({len(profile.known_devices)} known device(s))",
            )
        )

    if event.ip_address and event.ip_address not in profile.known_ips:
        deviations.append(
            Deviation(
                "new_ip",
                "ip_address",
                10,
                f"ip_address {event.ip_address!r} not seen before for this identity "
                f"({len(profile.known_ips)} known IP(s))",
            )
        )

    if event.geo_country and event.geo_country not in profile.known_countries:
        deviations.append(
            Deviation(
                "new_country",
                "geo_country",
                20,
                f"geo_country {event.geo_country!r} not seen before for this identity "
                f"(known: {sorted(profile.known_countries)})",
            )
        )

    if event.app_id and event.app_id not in profile.known_apps:
        deviations.append(
            Deviation(
                "new_app",
                "app_id",
                15,
                f"app_id {event.app_id!r} not seen before for this identity",
            )
        )

    if event.auth_protocol and event.auth_protocol not in profile.known_auth_protocols:
        deviations.append(
            Deviation(
                "new_auth_protocol",
                "auth_protocol",
                15,
                f"auth_protocol {event.auth_protocol!r} not seen before for this identity "
                f"(known: {sorted(profile.known_auth_protocols)})",
            )
        )

    if profile.login_hours and event.timestamp.hour not in profile.login_hours:
        deviations.append(
            Deviation(
                "unusual_login_hour",
                "timestamp",
                10,
                f"hour {event.timestamp.hour} UTC is outside this identity's usual "
                f"hours {sorted(profile.login_hours)}",
            )
        )

    if (
        event.bytes_transferred is not None
        and profile.max_bytes_transferred is not None
        and profile.max_bytes_transferred > 0
        and event.bytes_transferred > profile.max_bytes_transferred * VOLUME_ANOMALY_MULTIPLIER
    ):
        deviations.append(
            Deviation(
                "volume_anomaly",
                "bytes_transferred",
                25,
                f"bytes_transferred={event.bytes_transferred} exceeds "
                f"{VOLUME_ANOMALY_MULTIPLIER}x this identity's prior max "
                f"({profile.max_bytes_transferred})",
            )
        )

    return deviations
