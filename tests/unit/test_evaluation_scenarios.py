import random
from datetime import datetime, timezone

from app.evaluation.scenarios import (
    generate_attack_scenarios,
    generate_benign_edge_cases,
    generate_benign_population,
)
from app.pipeline import normalize_payload

BASE_TIME = datetime(2026, 9, 1, tzinfo=timezone.utc)


def test_benign_population_is_all_labeled_benign_with_unique_ids():
    rng = random.Random(1)
    events = generate_benign_population(rng, BASE_TIME, num_identities=3, events_per_identity=4)

    assert len(events) == 12
    assert all(e.label == "benign" for e in events)
    assert all(e.attack_id is None for e in events)
    assert len({e.event_id for e in events}) == len(events)  # all unique


def test_benign_edge_cases_are_labeled_benign():
    rng = random.Random(1)
    events = generate_benign_edge_cases(rng, BASE_TIME)
    assert events  # non-empty
    assert all(e.label == "benign" for e in events)


def test_every_generated_payload_normalizes_cleanly():
    """Ground truth is a separate list, not a field the pipeline ever
    sees - but the payloads themselves must still be valid inputs to it."""
    rng = random.Random(1)
    events = generate_benign_population(rng, BASE_TIME, num_identities=2, events_per_identity=2)
    events += generate_benign_edge_cases(rng, BASE_TIME)
    for instance in generate_attack_scenarios(rng, BASE_TIME, instances_per_type=1):
        events += instance.events

    for generated in events:
        event = normalize_payload(generated.payload)
        assert event.event_id == generated.event_id
        # the label/attack_id metadata never appears inside the payload itself
        assert "label" not in generated.payload
        assert "attack_id" not in generated.payload


def test_attack_scenarios_cover_all_six_types_with_requested_count():
    rng = random.Random(1)
    instances = generate_attack_scenarios(rng, BASE_TIME, instances_per_type=3)

    by_type: dict[str, int] = {}
    for instance in instances:
        by_type[instance.attack_type] = by_type.get(instance.attack_type, 0) + 1

    assert by_type == {"A1": 3, "A2": 3, "A3": 3, "A4": 3, "A5": 3, "A6": 3}


def test_each_scenario_instance_has_at_least_one_malicious_event():
    rng = random.Random(1)
    instances = generate_attack_scenarios(rng, BASE_TIME, instances_per_type=2)
    for instance in instances:
        assert instance.malicious_event_ids
        assert instance.malicious_event_ids <= {e.event_id for e in instance.events}


def test_scenario_instance_ids_and_event_ids_are_globally_unique():
    rng = random.Random(1)
    instances = generate_attack_scenarios(rng, BASE_TIME, instances_per_type=2)

    scenario_ids = [i.scenario_id for i in instances]
    assert len(scenario_ids) == len(set(scenario_ids))

    all_event_ids = [e.event_id for i in instances for e in i.events]
    assert len(all_event_ids) == len(set(all_event_ids))


def test_generation_is_deterministic_given_the_same_seed():
    events_a = generate_benign_population(random.Random(7), BASE_TIME, num_identities=2)
    events_b = generate_benign_population(random.Random(7), BASE_TIME, num_identities=2)
    # event_ids are random UUIDs (intentionally - see module docstring on
    # why ground truth is tracked by assigned id, not content), so compare
    # the deterministic parts instead: timestamps and the identity each
    # event belongs to (entra-shaped payloads carry actor_id inside `raw`).
    assert [e.timestamp for e in events_a] == [e.timestamp for e in events_b]
    upns_a = [e.payload["raw"]["userPrincipalName"] for e in events_a]
    upns_b = [e.payload["raw"]["userPrincipalName"] for e in events_b]
    assert upns_a == upns_b
