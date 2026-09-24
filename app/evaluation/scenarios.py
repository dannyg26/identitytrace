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


@dataclass
class BenignSequence:
    """One benign identity's activity, grouped as a unit.

    Phase 9 #12 wants a proper false-positive *rate* for the correlation
    layer, not just a raw incident count - and "rate of what" needs a
    denominator that means something. An individual event isn't it (one
    persona might contribute 1 event or 20); the sequence is: each
    BenignSequence is one "could this become a false-positive incident"
    trial, matching how a real analyst would think about it ("did this
    person's activity get wrongly escalated," not "did this one log
    line").
    """

    sequence_id: str
    persona: str
    identity: str
    events: list[GeneratedEvent] = field(default_factory=list)


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
    }
    if device_code:
        # Real telemetry (Phase 9B, 2026-09): authenticationProtocol is
        # documented on the signIn resource but was never populated across
        # 37 real sign-ins (device-code included) - this used to set it to
        # "deviceCode" here, which no real payload ever does. clientAppUsed
        # is what's actually populated; see IDT-ENTRA-003 and
        # app/normalizers/entra.py's _native_client_auth_protocol.
        raw["clientAppUsed"] = "Mobile Apps and Desktop clients"
    else:
        raw["authenticationProtocol"] = "basic" if legacy else "interactive"
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
) -> list[BenignSequence]:
    """Routine daily logins for a handful of lab identities - the "normal
    employee" persona from the blueprint's Layer 2 (§10.1.2). One
    BenignSequence per identity."""
    sequences: list[BenignSequence] = []
    for i in range(num_identities):
        upn = f"benign-user-{i}@eval.test"
        device_id = f"device-benign-{i}"
        ip = f"10.0.{i}.{rng.randint(1, 254)}"
        events: list[GeneratedEvent] = []
        for day in range(events_per_identity):
            ts = base_time + timedelta(days=day, hours=9, minutes=rng.randint(0, 30))
            event_id = _new_id()
            payload = _entra_signin(event_id, ts, upn, ip, device_id=device_id)
            events.append(GeneratedEvent(payload, event_id, ts, label="benign"))
        sequences.append(BenignSequence(f"routine-{i}", "routine_employee", upn, events))
    return sequences


def _persona_traveling_user(rng: random.Random, base_time: datetime) -> BenignSequence:
    """Normal baseline from New Jersey, then a business trip to
    California: new IP, new "network," different geography - but the
    same trusted device, and no OAuth/privilege/bulk-access follow-up.
    Should flag deviations (new_ip, new_country if we had US-state
    granularity - this project's geo_country is country-level, so a
    domestic trip only exercises new_ip here, which is still a real,
    correctly-flagged deviation) but must never form an incident."""
    upn = "traveling-employee@eval.test"
    home_ip = "10.0.9.5"
    trusted_device = "device-traveler-home"
    events: list[GeneratedEvent] = []
    for day in range(4):
        ts = base_time + timedelta(days=day, hours=9)
        event_id = _new_id()
        payload = _entra_signin(event_id, ts, upn, home_ip, device_id=trusted_device)
        events.append(GeneratedEvent(payload, event_id, ts, label="benign"))
    trip_ts = base_time + timedelta(days=5, hours=14)
    trip_event_id = _new_id()
    trip_payload = _entra_signin(
        trip_event_id, trip_ts, upn, "198.51.100.201",  # new IP ("new Wi-Fi"), same device
        device_id=trusted_device,
    )
    events.append(GeneratedEvent(trip_payload, trip_event_id, trip_ts, label="benign"))
    return BenignSequence("traveling-user", "traveling_user", upn, events)


def _persona_legitimate_admin(rng: random.Random, base_time: datetime) -> BenignSequence:
    """A real administrator's routine work: role assignments, from a
    known device/IP, spread out with ordinary activity between them.
    IdentityTrace has no per-role baseline in this version (a stated
    limitation - see docs/evaluation.md) - this persona instead tests the
    layer boundary that DOES exist: each role change should still surface
    as atomic evidence (IDT-ENTRA-006 - that's real, correct signal), but
    must not chain into a false incident just because an admin's job is
    naturally full of privilege-looking actions with no attack pattern
    behind them."""
    upn = "admin-user@eval.test"
    ip = "10.0.20.5"
    device_id = "device-admin-workstation"
    events: list[GeneratedEvent] = []
    for day in range(3):
        ts = base_time + timedelta(days=day, hours=9)
        eid = _new_id()
        events.append(GeneratedEvent(
            _entra_signin(eid, ts, upn, ip, device_id=device_id), eid, ts, label="benign",
        ))
    role_actions = ["Add member to role", "Add eligible member to role", "Update role"]
    for day, action in enumerate(role_actions):
        # After-hours maintenance - admins doing this at 22:00 is routine,
        # not itself evidence of anything (this project has no per-role
        # baseline to correctly contextualize "unusual hour for an admin,"
        # so the plain hour-based deviation check would still apply here -
        # see the persona's docstring above).
        ts = base_time + timedelta(days=3 + day, hours=22)
        eid = _new_id()
        events.append(GeneratedEvent(
            _entra_audit_role(eid, ts, upn, action), eid, ts, label="benign",
        ))
        # Deliberately NOT followed by any sensitive_resource_access event -
        # that's the difference between this persona and A5.
    return BenignSequence("legitimate-admin", "legitimate_admin", upn, events)


def _persona_developer_burst(rng: random.Random, base_time: datetime) -> BenignSequence:
    """A developer legitimately cloning/accessing many repos in a burst -
    automation, dependency pulls, code review across several projects.
    High event volume from an already-established token/device, no
    secret-named repos, no single transfer past the bulk-clone
    threshold. Should generate several low-severity IDT-GITHUB-001
    matches (correct - it IS token-driven repo access) but never
    complete IDT-CORR-005's sequence, since sensitive_resource_access
    never happens."""
    actor = "burst-dev"
    token_id = "pat-burst-dev"
    events: list[GeneratedEvent] = []
    for day in range(3):
        ts = base_time + timedelta(days=day, hours=10)
        eid = _new_id()
        events.append(GeneratedEvent(
            _github_event(eid, ts, actor, "repo.access", "acme/normal-repo", token_id),
            eid, ts, label="benign",
        ))
    burst_start = base_time + timedelta(days=3, hours=11)
    repo_pool = ["acme/website", "acme/internal-tools", "acme/docs", "acme/ci-config", "acme/normal-repo"]
    for i in range(12):
        ts = burst_start + timedelta(minutes=i * 2)
        eid = _new_id()
        events.append(GeneratedEvent(
            _github_event(eid, ts, actor, "repo.access", rng.choice(repo_pool), token_id),
            eid, ts, label="benign",
        ))
    return BenignSequence("developer-burst", "developer_burst", actor, events)


def _persona_new_laptop(rng: random.Random, base_time: datetime) -> BenignSequence:
    """A new corporate laptop: established baseline, then one clean
    device swap from the SAME IP/country - MFA satisfied, followed only
    by normal resource access. Isolates "new device alone" from
    "traveling_user"'s "new network alone," so a false positive on either
    axis shows up distinctly rather than being conflated."""
    upn = "new-laptop-employee@eval.test"
    ip = "10.0.30.5"
    old_device = "device-old-laptop"
    events: list[GeneratedEvent] = []
    for day in range(4):
        ts = base_time + timedelta(days=day, hours=9)
        eid = _new_id()
        events.append(GeneratedEvent(
            _entra_signin(eid, ts, upn, ip, device_id=old_device), eid, ts, label="benign",
        ))
    swap_ts = base_time + timedelta(days=5, hours=9)
    eid = _new_id()
    events.append(GeneratedEvent(
        _entra_signin(eid, swap_ts, upn, ip, device_id="device-new-laptop", mfa="success"),
        eid, swap_ts, label="benign",
    ))
    return BenignSequence("new-laptop", "new_corporate_laptop", upn, events)


def _persona_service_account(rng: random.Random, base_time: datetime) -> BenignSequence:
    """A service account (actor_type="service_principal", this project's
    schema already distinguishes this from "user" - see
    app/models/event.py) with consistent off-hours automated access. Its
    OWN baseline is built from its own off-hours pattern, so once
    established, 3 AM activity is exactly what "normal" looks like for
    this identity - unlike a human persona, where the same hour would be
    unusual."""
    identity = "svc-automation@eval.test"
    events: list[GeneratedEvent] = []
    for day in range(6):
        ts = base_time + timedelta(days=day, hours=3, minutes=rng.randint(0, 10))
        eid = _new_id()
        payload = _normalized_payload(
            eid, ts, identity, source="m365", event_type="file_access", action="AutomatedSync",
            result="success", actor_type="service_principal", ip_address="10.0.40.5",
            app_id="svc-automation-app",
        )
        events.append(GeneratedEvent(payload, eid, ts, label="benign"))
    return BenignSequence("service-account", "service_account", identity, events)


def _persona_bulk_download(rng: random.Random, base_time: datetime) -> BenignSequence:
    """A data analyst whose routine job is large exports. The point isn't
    "volume was under some threshold" in isolation - it's that full
    context (same device implicitly via a consistent identity, an
    established baseline, no OAuth/privilege signal anywhere nearby)
    explains it. Their own baseline should absorb this once established,
    so a similarly-sized transfer must NOT read as a volume anomaly after
    the first few exports set their normal max."""
    upn = "data-analyst@eval.test"
    events: list[GeneratedEvent] = []
    for day in range(5):
        ts = base_time + timedelta(days=day, hours=10)
        event_id = _new_id()
        payload = _normalized_payload(
            event_id, ts, upn,
            source="synthetic", event_type="file_download", action="export",
            result="success", bytes_transferred=50_000_000 + rng.randint(0, 5_000_000),
        )
        events.append(GeneratedEvent(payload, event_id, ts, label="benign"))
    return BenignSequence("bulk-download-analyst", "legitimate_bulk_download", upn, events)


_EDGE_CASE_BUILDERS = [
    _persona_traveling_user,
    _persona_legitimate_admin,
    _persona_developer_burst,
    _persona_new_laptop,
    _persona_service_account,
    _persona_bulk_download,
]


def generate_benign_edge_cases(rng: random.Random, base_time: datetime) -> list[BenignSequence]:
    """Behavior that looks unusual to a single atomic rule/deviation but
    is genuinely benign and never escalates - exactly what a false-positive
    check needs (blueprint §10.1.2: "benign edge cases that look
    suspicious in isolation"). Six personas, each evaluated on full
    context rather than any single signal in isolation - see Phase 9 #5:
    traveling user, legitimate administrator, developer API burst, new
    corporate laptop, service account, and legitimate bulk download."""
    return [builder(rng, base_time) for builder in _EDGE_CASE_BUILDERS]


def generate_ambiguous_singletons(rng: random.Random, base_time: datetime) -> list[BenignSequence]:
    """Phase 9 #11: each of these signals is individually plausible on
    its own - a new device, an OAuth consent, a repo access, a bulk
    download - each fired in complete isolation, nothing before or after
    it for the same identity. These prove correlation doesn't over-fire
    on a lone signal; only the *combination*, in order, within a window
    (what the attack generators build) should complete a chain. Distinct
    from generate_benign_edge_cases: those personas have a full
    multi-event history: these are deliberately the minimal case."""
    sequences: list[BenignSequence] = []

    # Lone new device - one signin from a never-before-seen device, no
    # baseline established beforehand (so this alone can't even trigger
    # the new_device deviation - MIN_HISTORY_FOR_BASELINE isn't met - but
    # it's included specifically to prove that too: cold-start isn't
    # mistaken for compromise either).
    upn1 = "singleton-device@eval.test"
    ts1 = base_time + timedelta(hours=9)
    eid1 = _new_id()
    sequences.append(BenignSequence(
        "singleton-new-device", "ambiguous_singleton", upn1,
        [GeneratedEvent(
            _entra_signin(eid1, ts1, upn1, "10.0.50.5", device_id="device-singleton"),
            eid1, ts1, label="benign",
        )],
    ))

    # Lone OAuth consent to a mainstream-looking productivity app -
    # nothing before, nothing after.
    upn2 = "singleton-consent@eval.test"
    ts2 = base_time + timedelta(hours=9)
    eid2 = _new_id()
    sequences.append(BenignSequence(
        "singleton-oauth-consent", "ambiguous_singleton", upn2,
        [GeneratedEvent(
            _entra_oauth_consent(eid2, ts2, upn2, "TeamCalendarSync", ["Files.Read.All"]),
            eid2, ts2, label="benign",
        )],
    ))

    # Lone repo access via PAT - one clone, nothing before or after.
    actor3 = "singleton-repo-user"
    ts3 = base_time + timedelta(hours=9)
    eid3 = _new_id()
    sequences.append(BenignSequence(
        "singleton-repo-access", "ambiguous_singleton", actor3,
        [GeneratedEvent(
            _github_event(eid3, ts3, actor3, "repo.access", "acme/normal-repo", "pat-singleton"),
            eid3, ts3, label="benign",
        )],
    ))

    # Lone bulk download - one large transfer, nothing before or after.
    upn4 = "singleton-bulk@eval.test"
    ts4 = base_time + timedelta(hours=9)
    eid4 = _new_id()
    sequences.append(BenignSequence(
        "singleton-bulk-download", "ambiguous_singleton", upn4,
        [GeneratedEvent(
            _normalized_payload(
                eid4, ts4, upn4, event_type="file_download", action="download",
                result="success", bytes_transferred=300_000_000,
            ),
            eid4, ts4, label="benign",
        )],
    ))

    return sequences


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


_A2_MALICIOUS_APPS = [
    ("EvilReportingApp", ["Files.Read.All"]),
    ("QuickBooksSync", ["Mail.Read", "offline_access"]),
    ("SalesDashboardConnector", ["Directory.ReadWrite.All"]),
    ("TeamCalendarSync", ["Mail.ReadWrite", "offline_access"]),
]
_A2_SENSITIVE_RESOURCE_TYPES = ["mailbox", "secret", "role"]


def _make_a2(rng: random.Random, base_time: datetime, index: int) -> ScenarioInstance:
    """A2: malicious OAuth consent. Satisfies IDT-CORR-001."""
    upn = f"a2-victim-{index}@eval.test"
    attack_start = base_time + timedelta(days=10 + index // 4, hours=9, minutes=(index % 4) * 12)
    app_name, scopes = _A2_MALICIOUS_APPS[index % len(_A2_MALICIOUS_APPS)]
    resource_type = _A2_SENSITIVE_RESOURCE_TYPES[index % len(_A2_SENSITIVE_RESOURCE_TYPES)]
    eid1 = _new_id()
    ev1 = GeneratedEvent(
        _entra_signin(eid1, attack_start, upn, f"198.51.{index % 250}.10", device_code=True),
        eid1, attack_start, label="malicious", attack_id=f"A2-{index}", attack_type="A2",
    )
    consent_ts = attack_start + timedelta(minutes=rng.randint(2, 8))
    eid2 = _new_id()
    ev2 = GeneratedEvent(
        _entra_oauth_consent(eid2, consent_ts, upn, app_name, scopes),
        eid2, consent_ts, label="malicious", attack_id=f"A2-{index}", attack_type="A2",
    )
    access_ts = consent_ts + timedelta(minutes=rng.randint(2, 8))
    eid3 = _new_id()
    ev3 = GeneratedEvent(
        _normalized_payload(
            eid3, access_ts, upn, event_type="file_access", action="read",
            result="success", resource_type=resource_type,
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


_A4_NORMAL_REPOS = ["acme/normal-repo", "acme/website", "acme/internal-tools", "acme/docs"]
_A4_SENSITIVE_REPOS = ["acme/secret-infra", "acme/prod-credentials", "acme/vault-configs"]


def _make_a4(rng: random.Random, base_time: datetime, index: int) -> ScenarioInstance:
    """A4: developer token compromise. Satisfies IDT-CORR-005
    (repo_access -> sensitive_resource_access -> bulk_data_access)."""
    actor = f"a4-dev-{index}"
    token_id = f"pat-a4-{index}"
    attack_start = base_time + timedelta(days=20 + index // 4, hours=2, minutes=(index % 4) * 15)
    normal_repo = _A4_NORMAL_REPOS[index % len(_A4_NORMAL_REPOS)]
    sensitive_repo = _A4_SENSITIVE_REPOS[index % len(_A4_SENSITIVE_REPOS)]
    clone_bytes = 150_000_000 + rng.randint(0, 100_000_000)
    eid1 = _new_id()
    ev1 = GeneratedEvent(
        _github_event(eid1, attack_start, actor, "repo.access", normal_repo, token_id),
        eid1, attack_start, label="malicious", attack_id=f"A4-{index}", attack_type="A4",
    )
    sensitive_ts = attack_start + timedelta(minutes=rng.randint(2, 6))
    eid2 = _new_id()
    ev2 = GeneratedEvent(
        _github_event(eid2, sensitive_ts, actor, "repo.access", sensitive_repo, token_id),
        eid2, sensitive_ts, label="malicious", attack_id=f"A4-{index}", attack_type="A4",
    )
    clone_ts = sensitive_ts + timedelta(minutes=rng.randint(2, 8))
    eid3 = _new_id()
    ev3 = GeneratedEvent(
        _github_event(
            eid3, clone_ts, actor, "git.clone", sensitive_repo, token_id,
            transfer_size_bytes=clone_bytes,
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
