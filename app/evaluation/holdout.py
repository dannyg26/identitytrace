"""Frozen holdout dataset generator (Phase 9 #6).

The detector's rules/correlation logic and the main synthetic generator
(app/evaluation/scenarios.py) were developed together - same author, same
sitting, each informed by watching the other's output. That's a real risk
of circular evaluation: the generator could unconsciously produce exactly
what the detector expects. A held-out, differently-parameterized set is
the check.

generate_holdout_dataset() reuses the same underlying event builders as
scenarios.py (this project does not reimplement Entra/GitHub/M365 payload
construction twice - that would just be two places to keep schema-accurate
instead of one) but composes them differently:

- a different seed and base_time than the main generator's default runs
- a new benign persona not present in the main set (shared_workstation)
- an attack *combination* none of the five correlation rules were
  specifically written around: a new-device/new-country signin followed
  by a role assignment and sensitive access, all for one identity. Any
  one of IDT-CORR-002's or IDT-CORR-003's *individual* signals is
  present, but the full chain is a genuinely different shape than either
  rule's own sequence - an honest test of whether the architecture
  generalizes even a little past the exact five patterns it was tuned
  against, not just a reshuffled copy of the original twelve scenarios.

FREEZING: this module only *generates*. The actual frozen artifact is
tests/fixtures/holdout/holdout_v1.json, written once by
scripts/freeze_holdout.py and checked into git. Every evaluation against
"the holdout set" loads that file (app/evaluation/holdout_runner.py) -
never calls this module directly - so a later change here, or to
scenarios.py's shared builders, cannot silently change what "the holdout
set" means after it's frozen. See docs/holdout.md for the freeze
discipline and the result-tracking log.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from app.evaluation.scenarios import (
    BenignSequence,
    GeneratedEvent,
    ScenarioInstance,
    _entra_audit_role,
    _entra_signin,
    _new_id,
    _normalized_payload,
    generate_ambiguous_singletons,
    generate_attack_scenarios,
    generate_benign_edge_cases,
    generate_benign_population,
)

HOLDOUT_SEED = 999
HOLDOUT_BASE_TIME = datetime(2027, 1, 5, tzinfo=timezone.utc)  # deliberately not the main generator's date


def _persona_shared_workstation(rng: random.Random, base_time: datetime) -> list[BenignSequence]:
    """Multiple identities briefly using the same physical device (a lab
    kiosk, a shared front-desk workstation). Not in the main benign set -
    tests that per-identity baselines don't cross-contaminate just
    because a device_id repeats across different actor_ids."""
    device_id = "device-shared-kiosk"
    ip = "10.0.60.5"
    sequences: list[BenignSequence] = []
    for i in range(3):
        upn = f"kiosk-user-{i}@eval.test"
        events: list[GeneratedEvent] = []
        for day in range(3):
            ts = base_time + timedelta(days=day, hours=9, minutes=i * 5)
            eid = _new_id()
            events.append(GeneratedEvent(
                _entra_signin(eid, ts, upn, ip, device_id=device_id), eid, ts, label="benign",
            ))
        sequences.append(BenignSequence(f"shared-workstation-{i}", "shared_workstation", upn, events))
    return sequences


def _make_combined_new_location_privilege_escalation(
    rng: random.Random, base_time: datetime, index: int
) -> ScenarioInstance:
    """A held-out attack combination: new device+country (A1's opening),
    then a role assignment and sensitive access (A5's own sequence) -
    NOT one of the five correlation rules' exact patterns. IDT-CORR-003
    (privilege_escalation -> sensitive_resource_access) should still pick
    out the relevant sub-chain even with an unrelated signin mixed in
    ahead of it; IDT-CORR-002 (new_device -> new_country ->
    bulk_data_access) should NOT fire, since no bulk_data_access signal
    ever occurs here. Both are real, checkable predictions - see
    docs/holdout.md for what actually happened when this ran."""
    upn = f"holdout-combo-{index}@eval.test"
    home_ip, home_device = f"10.9.{index}.5", f"device-combo-home-{index}"
    events: list[GeneratedEvent] = []
    for day in range(3):
        ts = base_time + timedelta(days=day, hours=9)
        eid = _new_id()
        events.append(GeneratedEvent(
            _entra_signin(eid, ts, upn, home_ip, device_id=home_device), eid, ts, label="benign",
        ))

    attack_start = base_time + timedelta(days=4, hours=5)
    eid1 = _new_id()
    ev1 = GeneratedEvent(
        _entra_signin(
            eid1, attack_start, upn, f"203.0.{index}.50",
            device_id=f"device-combo-new-{index}", country="CN",
        ),
        eid1, attack_start, label="malicious", attack_id=f"HOLD-COMBO-{index}", attack_type="COMBO",
    )
    role_ts = attack_start + timedelta(minutes=rng.randint(3, 10))
    eid2 = _new_id()
    ev2 = GeneratedEvent(
        _entra_audit_role(eid2, role_ts, upn, "Add member to role"),
        eid2, role_ts, label="malicious", attack_id=f"HOLD-COMBO-{index}", attack_type="COMBO",
    )
    access_ts = role_ts + timedelta(minutes=rng.randint(3, 10))
    eid3 = _new_id()
    ev3 = GeneratedEvent(
        _normalized_payload(
            eid3, access_ts, upn, event_type="file_access", action="read",
            result="success", resource_type="secret",
        ),
        eid3, access_ts, label="malicious", attack_id=f"HOLD-COMBO-{index}", attack_type="COMBO",
    )
    events.extend([ev1, ev2, ev3])
    return ScenarioInstance(f"HOLD-COMBO-{index}", "COMBO", upn, attack_start, events)


def generate_holdout_dataset(
    seed: int = HOLDOUT_SEED,
    base_time: datetime = HOLDOUT_BASE_TIME,
    scenarios_per_type: int = 3,
    combo_instances: int = 3,
) -> dict:
    """Everything the holdout set contains: the main generator's own
    families (at a different seed/date - still not identical instances),
    plus what's new here. Returns a plain dict ready for JSON
    serialization (see scripts/freeze_holdout.py)."""
    rng = random.Random(seed)

    benign_sequences = generate_benign_population(rng, base_time, num_identities=4)
    benign_sequences += generate_benign_edge_cases(rng, base_time)
    benign_sequences += generate_ambiguous_singletons(rng, base_time)
    benign_sequences += _persona_shared_workstation(rng, base_time)

    instances = generate_attack_scenarios(rng, base_time, instances_per_type=scenarios_per_type)
    instances += [
        _make_combined_new_location_privilege_escalation(rng, base_time, i)
        for i in range(combo_instances)
    ]

    return {
        "seed": seed,
        "base_time": base_time.isoformat(),
        "benign_sequences": [
            {
                "sequence_id": seq.sequence_id,
                "persona": seq.persona,
                "identity": seq.identity,
                "events": [_serialize_event(e) for e in seq.events],
            }
            for seq in benign_sequences
        ],
        "attack_scenarios": [
            {
                "scenario_id": inst.scenario_id,
                "attack_type": inst.attack_type,
                "identity": inst.identity,
                "start_time": inst.start_time.isoformat(),
                "events": [_serialize_event(e) for e in inst.events],
            }
            for inst in instances
        ],
    }


def _serialize_event(e: GeneratedEvent) -> dict:
    return {
        "payload": e.payload,
        "event_id": e.event_id,
        "timestamp": e.timestamp.isoformat(),
        "label": e.label,
        "attack_id": e.attack_id,
        "attack_type": e.attack_type,
    }
