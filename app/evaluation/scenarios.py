"""Reproducible benign + labeled-attack scenario generators (blueprint
§10.1: fixed seed, ground truth kept outside the detection path).

Every generated event is a `GeneratedEvent`: the exact payload you'd POST
to `/api/events`, its expected event_id (assigned up front, not left to
the normalizer's default, so ground truth can be tracked precisely), and
a label. Labels never travel inside the payload the pipeline sees - they
live only in the lists this module returns, exactly the blueprint's
"store labels outside the production detection path so the engine cannot
accidentally see the answer" rule (§10.1.3).

Attack scenarios are built as: a short benign baseline for a fresh
identity (establishing "normal" - Layer 2), followed immediately by the
malicious chain (Layer 3) that's designed to satisfy one specific
correlation rule from `correlations/`. This mirrors the blueprint's
three-layer dataset design (§10.1.2) at a scale appropriate to this
project - not full BOTS-style background noise, but real benign history
an identity's baseline is genuinely built from.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


@dataclass
class GeneratedEvent:
    payload: dict
    event_id: str
    timestamp: datetime
    label: str  # "benign" | "malicious"
    attack_id: Optional[str] = None
    attack_type: Optional[str] = None


@dataclass
class ScenarioInstance:
    scenario_id: str
    attack_type: str
    identity: str
    start_time: datetime  # timestamp of the first malicious event
    events: list[GeneratedEvent] = field(default_factory=list)

    @property
    def malicious_event_ids(self) -> set[str]:
        return {e.event_id for e in self.events if e.label == "malicious"}


def _new_id() -> str:
    return str(uuid.uuid4())


def _normalized_payload(event_id: str, timestamp: datetime, actor_id: str, **fields) -> dict:
    payload = {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "actor_id": actor_id,
        **fields,
    }
    payload.setdefault("source", "synthetic")
    payload.setdefault("actor_type", "user")
    return payload


def _entra_signin(
    event_id: str,
    timestamp: datetime,
    upn: str,
    ip: str,
    device_id: Optional[str] = None,
    country: str = "US",
    device_code: bool = False,
    legacy: bool = False,
    mfa: Optional[str] = None,
) -> dict:
    raw = {
        "id": event_id,
        "createdDateTime": timestamp.isoformat().replace("+00:00", "Z"),
        "userPrincipalName": upn,
        "appId": "app-baseline",
        "ipAddress": ip,
        "location": {"countryOrRegion": country},
        "status": {"errorCode": 0},
        "authenticationProtocol": "deviceCode" if device_code else ("basic" if legacy else "interactive"),
    }
    if device_id:
        raw["deviceDetail"] = {"deviceId": device_id}
    if mfa:
        raw["mfaDetail"] = {"result": mfa}
    return {"source": "entra", "raw": raw}


def _entra_audit_role(event_id: str, timestamp: datetime, upn: str, action: str) -> dict:
    raw = {
        "id": event_id,
        # "category" here is the real directoryAudit field (real value:
        # "RoleManagement") - NOT a dispatch marker. Dispatch (see
        # app/normalizers/entra.py's normalize()) keys on activityDateTime
        # vs. createdDateTime, both real, non-colliding fields.
        "category": "RoleManagement",
        "activityDateTime": timestamp.isoformat().replace("+00:00", "Z"),
        "activityDisplayName": action,
        "initiatedBy": {"user": {"id": f"{upn}-id", "userPrincipalName": upn}},
        "targetResources": [],
        "result": "success",
    }
    return {"source": "entra", "raw": raw}


def _entra_oauth_consent(event_id: str, timestamp: datetime, upn: str, app_name: str, scopes: list[str]) -> dict:
    raw = {
        "id": event_id,
        "category": "ApplicationManagement",  # real field/value - see _entra_audit_role's comment
        "activityDateTime": timestamp.isoformat().replace("+00:00", "Z"),
        "activityDisplayName": "Consent to application",
        "initiatedBy": {"user": {"id": f"{upn}-id", "userPrincipalName": upn}},
        "targetResources": [
            {
                "type": "Application",
                "id": app_name.lower(),
                "displayName": app_name,
                "modifiedProperties": [
                    {"displayName": "ConsentAction.Permissions", "newValue": str(scopes).replace("'", '"')}
                ],
            }
        ],
        "result": "success",
    }
    return {"source": "entra", "raw": raw}


def _github_event(
    event_id: str,
    timestamp: datetime,
    actor: str,
    action: str,
    repo: str,
    token_id: str,
    transfer_size_bytes: Optional[int] = None,
) -> dict:
    raw = {
        "_document_id": event_id,
        "action": action,
        "actor": actor,
        "actor_ip": "198.51.100.20",
        "repo": repo,
        "token_id": token_id,
        "token_scopes": ["repo"],
        "created_at": timestamp.isoformat().replace("+00:00", "Z"),
    }
    if transfer_size_bytes is not None:
        raw["transfer_size_bytes"] = transfer_size_bytes
    return {"source": "github", "raw": raw}


def generate_benign_population(
    rng: random.Random,
    base_time: datetime,
    num_identities: int = 5,
    events_per_identity: int = 6,
) -> list[GeneratedEvent]:
    """Routine daily logins for a handful of lab identities - the "normal
    employee" persona from the blueprint's Layer 2 (§10.1.2)."""
    events: list[GeneratedEvent] = []
    for i in range(num_identities):
        upn = f"benign-user-{i}@eval.test"
        device_id = f"device-benign-{i}"
        ip = f"10.0.{i}.{rng.randint(1, 254)}"
        for day in range(events_per_identity):
            ts = base_time + timedelta(days=day, hours=9, minutes=rng.randint(0, 30))
            event_id = _new_id()
            payload = _entra_signin(event_id, ts, upn, ip, device_id=device_id)
            events.append(GeneratedEvent(payload, event_id, ts, label="benign"))
    return events


def generate_benign_edge_cases(rng: random.Random, base_time: datetime) -> list[GeneratedEvent]:
    """Behavior that looks unusual to a single atomic rule/deviation but
    is genuinely benign and never escalates - exactly what a false-positive
    check needs (blueprint §10.1.2: "benign edge cases that look
    suspicious in isolation")."""
    events: list[GeneratedEvent] = []

    # A traveling employee: normal baseline, then one trip - new device
    # AND new country, but no OAuth/privilege/bulk-access follow-up. Should
    # flag deviations (that's correct - it IS new) but never form an
    # incident, since the rest of any attack chain never happens.
    upn = "traveling-employee@eval.test"
    home_ip = "10.0.9.5"
    home_device = "device-traveler-home"
    for day in range(4):
        ts = base_time + timedelta(days=day, hours=9)
        event_id = _new_id()
        payload = _entra_signin(event_id, ts, upn, home_ip, device_id=home_device)
        events.append(GeneratedEvent(payload, event_id, ts, label="benign"))
    trip_ts = base_time + timedelta(days=5, hours=14)
    trip_event_id = _new_id()
    trip_payload = _entra_signin(
        trip_event_id, trip_ts, upn, "203.0.113.200",
        device_id="device-traveler-trip", country="FR",
    )
    events.append(GeneratedEvent(trip_payload, trip_event_id, trip_ts, label="benign"))

    # A data analyst whose routine job is large exports - their own
    # baseline should absorb this once established, so it must NOT read as
    # a volume anomaly after the first few exports set their normal max.
    upn2 = "data-analyst@eval.test"
    for day in range(5):
        ts = base_time + timedelta(days=day, hours=10)
        event_id = _new_id()
        payload = _normalized_payload(
            event_id, ts, upn2,
            source="synthetic", event_type="file_download", action="export",
            result="success", bytes_transferred=50_000_000 + rng.randint(0, 5_000_000),
        )
        events.append(GeneratedEvent(payload, event_id, ts, label="benign"))

    return events


def _make_a1(rng: random.Random, base_time: datetime, index: int) -> ScenarioInstance:
    """A1: device-code phishing -> new device/country -> bulk access.
    Satisfies IDT-CORR-002 (new_device -> new_country -> bulk_data_access)."""
    upn = f"a1-victim-{index}@eval.test"
    home_ip, home_device = f"10.1.{index}.5", f"device-a1-home-{index}"
    events: list[GeneratedEvent] = []
    for day in range(3):
        ts = base_time + timedelta(days=day, hours=9)
        eid = _new_id()
        events.append(GeneratedEvent(
            _entra_signin(eid, ts, upn, home_ip, device_id=home_device), eid, ts, label="benign",
        ))

    attack_start = base_time + timedelta(days=4, hours=3, minutes=rng.randint(0, 10))
    eid1 = _new_id()
    ev1 = GeneratedEvent(
        _entra_signin(
            eid1, attack_start, upn, f"198.51.{index}.99",
            device_id=f"device-a1-attacker-{index}", country="RU",
        ),
        eid1, attack_start, label="malicious", attack_id=f"A1-{index}", attack_type="A1",
    )
    bulk_ts = attack_start + timedelta(minutes=rng.randint(5, 20))
    eid2 = _new_id()
    ev2 = GeneratedEvent(
        _normalized_payload(
            eid2, bulk_ts, upn, event_type="file_download", action="download",
            result="success", bytes_transferred=400_000_000,
        ),
        eid2, bulk_ts, label="malicious", attack_id=f"A1-{index}", attack_type="A1",
    )
    events.extend([ev1, ev2])
    return ScenarioInstance(f"A1-{index}", "A1", upn, attack_start, events)


def _make_a2(rng: random.Random, base_time: datetime, index: int) -> ScenarioInstance:
    """A2: malicious OAuth consent. Satisfies IDT-CORR-001."""
    upn = f"a2-victim-{index}@eval.test"
    attack_start = base_time + timedelta(days=10 + index, hours=9)
    eid1 = _new_id()
    ev1 = GeneratedEvent(
        _entra_signin(eid1, attack_start, upn, f"198.51.{index}.10", device_code=True),
        eid1, attack_start, label="malicious", attack_id=f"A2-{index}", attack_type="A2",
    )
    consent_ts = attack_start + timedelta(minutes=rng.randint(2, 8))
    eid2 = _new_id()
    ev2 = GeneratedEvent(
        _entra_oauth_consent(eid2, consent_ts, upn, "EvilReportingApp", ["Files.Read.All"]),
        eid2, consent_ts, label="malicious", attack_id=f"A2-{index}", attack_type="A2",
    )
    access_ts = consent_ts + timedelta(minutes=rng.randint(2, 8))
    eid3 = _new_id()
    ev3 = GeneratedEvent(
        _normalized_payload(
            eid3, access_ts, upn, event_type="file_access", action="read",
            result="success", resource_type="mailbox",
        ),
        eid3, access_ts, label="malicious", attack_id=f"A2-{index}", attack_type="A2",
    )
    return ScenarioInstance(f"A2-{index}", "A2", upn, attack_start, [ev1, ev2, ev3])


def _make_a3(rng: random.Random, base_time: datetime, index: int) -> ScenarioInstance:
    """A3: session/token theft. Satisfies IDT-CORR-004
    (weak_auth_session -> new_ip -> bulk_data_access). Needs a benign
    baseline first, same as A1 - "new_ip" is a Phase 3 deviation, and
    deviations need an established profile before anything can look new."""
    upn = f"a3-victim-{index}@eval.test"
    home_ip = f"10.3.{index}.5"
    events: list[GeneratedEvent] = []
    for day in range(3):
        ts = base_time + timedelta(days=day, hours=8)
        eid = _new_id()
        events.append(GeneratedEvent(
            _entra_signin(eid, ts, upn, home_ip), eid, ts, label="benign",
        ))

    attack_start = base_time + timedelta(days=15 + index, hours=11)
    eid1 = _new_id()
    ev1 = GeneratedEvent(
        _entra_signin(eid1, attack_start, upn, f"198.51.{index}.20", mfa="not_present"),
        eid1, attack_start, label="malicious", attack_id=f"A3-{index}", attack_type="A3",
    )
    events.append(ev1)
    bulk_ts = attack_start + timedelta(minutes=rng.randint(1, 5))
    eid2 = _new_id()
    ev2 = GeneratedEvent(
        _normalized_payload(
            eid2, bulk_ts, upn, event_type="file_download", action="download",
            result="success", bytes_transferred=350_000_000,
        ),
        eid2, bulk_ts, label="malicious", attack_id=f"A3-{index}", attack_type="A3",
    )
    events.append(ev2)
    return ScenarioInstance(f"A3-{index}", "A3", upn, attack_start, events)


def _make_a4(rng: random.Random, base_time: datetime, index: int) -> ScenarioInstance:
    """A4: developer token compromise. Satisfies IDT-CORR-005
    (repo_access -> sensitive_resource_access -> bulk_data_access)."""
    actor = f"a4-dev-{index}"
    token_id = f"pat-a4-{index}"
    attack_start = base_time + timedelta(days=20 + index, hours=2)
    eid1 = _new_id()
    ev1 = GeneratedEvent(
        _github_event(eid1, attack_start, actor, "repo.access", "acme/normal-repo", token_id),
        eid1, attack_start, label="malicious", attack_id=f"A4-{index}", attack_type="A4",
    )
    sensitive_ts = attack_start + timedelta(minutes=rng.randint(2, 6))
    eid2 = _new_id()
    ev2 = GeneratedEvent(
        _github_event(eid2, sensitive_ts, actor, "repo.access", "acme/secret-infra", token_id),
        eid2, sensitive_ts, label="malicious", attack_id=f"A4-{index}", attack_type="A4",
    )
    clone_ts = sensitive_ts + timedelta(minutes=rng.randint(2, 8))
    eid3 = _new_id()
    ev3 = GeneratedEvent(
        _github_event(
            eid3, clone_ts, actor, "git.clone", "acme/secret-infra", token_id,
            transfer_size_bytes=150_000_000,
        ),
        eid3, clone_ts, label="malicious", attack_id=f"A4-{index}", attack_type="A4",
    )
    return ScenarioInstance(f"A4-{index}", "A4", actor, attack_start, [ev1, ev2, ev3])


def _make_a5(rng: random.Random, base_time: datetime, index: int) -> ScenarioInstance:
    """A5: privilege escalation. Satisfies IDT-CORR-003
    (privilege_escalation -> sensitive_resource_access)."""
    upn = f"a5-victim-{index}@eval.test"
    attack_start = base_time + timedelta(days=25 + index, hours=13)
    eid1 = _new_id()
    ev1 = GeneratedEvent(
        _entra_audit_role(eid1, attack_start, upn, "Add member to role"),
        eid1, attack_start, label="malicious", attack_id=f"A5-{index}", attack_type="A5",
    )
    access_ts = attack_start + timedelta(minutes=rng.randint(3, 15))
    eid2 = _new_id()
    ev2 = GeneratedEvent(
        _normalized_payload(
            eid2, access_ts, upn, event_type="file_access", action="read",
            result="success", resource_type="secret",
        ),
        eid2, access_ts, label="malicious", attack_id=f"A5-{index}", attack_type="A5",
    )
    return ScenarioInstance(f"A5-{index}", "A5", upn, attack_start, [ev1, ev2])


def _make_a6(rng: random.Random, base_time: datetime, index: int) -> ScenarioInstance:
    """A6: SaaS data theft as a standalone bulk transfer - deliberately
    NOT part of any 2+ step correlation sequence. This is an honest,
    intentional coverage gap: it should be caught by the isolated
    IDT-XDOMAIN-001 rule but will never form an incident on its own,
    since no correlation rule fires on a single signal. See
    docs/evaluation.md for why that's reported rather than papered over.
    """
    upn = f"a6-victim-{index}@eval.test"
    attack_start = base_time + timedelta(days=30 + index, hours=16)
    eid = _new_id()
    ev = GeneratedEvent(
        _normalized_payload(
            eid, attack_start, upn, source="m365", event_type="file_download",
            action="FileDownloaded", result="success", bytes_transferred=600_000_000,
        ),
        eid, attack_start, label="malicious", attack_id=f"A6-{index}", attack_type="A6",
    )
    return ScenarioInstance(f"A6-{index}", "A6", upn, attack_start, [ev])


_SCENARIO_BUILDERS = {
    "A1": _make_a1,
    "A2": _make_a2,
    "A3": _make_a3,
    "A4": _make_a4,
    "A5": _make_a5,
    "A6": _make_a6,
}


def generate_attack_scenarios(
    rng: random.Random, base_time: datetime, instances_per_type: int = 2
) -> list[ScenarioInstance]:
    instances: list[ScenarioInstance] = []
    for builder in _SCENARIO_BUILDERS.values():
        for i in range(instances_per_type):
            instances.append(builder(rng, base_time, i))
    return instances
