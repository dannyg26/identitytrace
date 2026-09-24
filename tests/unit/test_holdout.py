"""Unit tests for the holdout generator and its serialization round-trip
(app/evaluation/holdout.py). The actual frozen file
(tests/fixtures/holdout/holdout_v1.json) is exercised by
test_holdout_runner.py; these tests cover the generator itself and are
not affected by whether that file has been regenerated."""

from app.evaluation.holdout import generate_holdout_dataset


def _fingerprint(dataset: dict) -> list:
    """event_ids (and the copies of them embedded inside raw payloads -
    entra's "id", github's "_document_id", etc.) are random UUIDs, not
    seeded by rng - same intentional design as the main generator (see
    scenarios.py's module docstring). Determinism is checked on
    everything else: counts, personas/attack types, identities,
    timestamps, and labels, in order.
    """
    fp = []
    for s in dataset["benign_sequences"]:
        fp.append((s["persona"], s["identity"], [(e["timestamp"], e["label"]) for e in s["events"]]))
    for i in dataset["attack_scenarios"]:
        fp.append((i["attack_type"], i["identity"], [(e["timestamp"], e["label"]) for e in i["events"]]))
    return fp


def test_holdout_dataset_is_deterministic():
    first = generate_holdout_dataset(seed=1)
    second = generate_holdout_dataset(seed=1)
    assert _fingerprint(first) == _fingerprint(second)


def test_holdout_includes_a_persona_not_in_the_main_generator():
    dataset = generate_holdout_dataset(seed=1)
    personas = {s["persona"] for s in dataset["benign_sequences"]}
    assert "shared_workstation" in personas


def test_holdout_includes_a_novel_attack_combination():
    dataset = generate_holdout_dataset(seed=1)
    attack_types = {i["attack_type"] for i in dataset["attack_scenarios"]}
    assert "COMBO" in attack_types
    # still has the six original families too - this isn't a replacement
    assert {"A1", "A2", "A3", "A4", "A5", "A6"} <= attack_types


def test_holdout_uses_a_different_seed_and_base_time_than_main_generator_defaults():
    from app.evaluation.harness import DEFAULT_BASE_TIME
    from app.evaluation.holdout import HOLDOUT_BASE_TIME, HOLDOUT_SEED

    assert HOLDOUT_SEED != 42  # the main harness's documented default seed
    assert HOLDOUT_BASE_TIME != DEFAULT_BASE_TIME


def test_every_holdout_event_is_json_serializable():
    import json

    dataset = generate_holdout_dataset(seed=1, scenarios_per_type=1, combo_instances=1)
    json.dumps(dataset)  # raises if anything isn't serializable
