"""Entity-bridged (cross-identity) correlation: engine, schema, and the
guards that keep the rule bounded to the telemetry it was validated on.

These run against the real shipped IDT-CORR-006 - not a copy - so a change
to the YAML that weakens it fails here. Every negative case below is one
the design explicitly forbids (docs/evaluation.md, "A2 Cross-Identity
Correlation v2").
"""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.correlation.engine import (
    evaluate_bridged_rule,
    evaluate_correlation_rule,
    find_bridged_chains,
)
from app.correlation.loader import load_correlation_rules
from app.correlation.schema import CorrelationRule
from app.correlation.signals import SignalOccurrence
from app.detections.loader import load_rules

RULE = {r.id: r for r in load_correlation_rules()}["IDT-CORR-006"]

USER = "idt-test-user3@example.test"
OTHER_USER = "idt-test-user2@example.test"
ADMIN = "idt-admin@example.test"
SP = "11111111-1111-4111-8111-111111111111"
OTHER_SP = "22222222-2222-4222-8222-222222222222"
T0 = datetime(2026, 9, 15, 18, 17, 49, tzinfo=timezone.utc)  # the real block time

_n = 0


def sig(signal_type, offset_seconds, actor, entity=SP, weight=15, event_id=None):
    global _n
    _n += 1
    return SignalOccurrence(
        signal_type=signal_type,
        timestamp=T0 + timedelta(seconds=offset_seconds),
        event_id=event_id or f"e{_n}",
        actor_id=actor,
        kind="detection",
        source_id="test",
        weight=weight,
        label=signal_type,
        entity=entity,
    )


def block(offset=0, actor=USER, entity=SP):
    return sig("admin_consent_required", offset, actor, entity)


def consent(offset=32, actor=ADMIN, entity=SP):
    return sig("risky_oauth_consent", offset, actor, entity, weight=45)


def success(offset=158, actor=USER, entity=SP):
    return sig("new_session_context", offset, actor, entity)


def chains(*signals):
    return find_bridged_chains(list(signals), RULE)


# ---- the validated real sequence (real offsets: 0s / +32s / +158s) ----

def test_real_validated_sequence_correlates():
    result = chains(block(), consent(), success())
    assert len(result) == 1
    assert [s.signal_type for s in result[0]] == [
        "admin_consent_required", "risky_oauth_consent", "new_session_context",
    ]
    assert [s.actor_id for s in result[0]] == [USER, ADMIN, USER]


def test_admin_may_be_the_requester_too():
    """'may be a different identity', not 'must': one identity that is both
    blocked and able to grant consent is still the same chain."""
    assert len(chains(block(), consent(actor=USER), success())) == 1


def test_signal_order_in_the_input_list_does_not_matter():
    a, b, c = block(), consent(), success()
    assert len(chains(c, a, b)) == 1
    assert len(chains(b, c, a)) == 1


# ---- negatives: each one thing the design must refuse ----

def test_different_service_principal_on_consent_does_not_correlate():
    assert chains(block(), consent(entity=OTHER_SP), success()) == []


def test_different_service_principal_on_success_does_not_correlate():
    assert chains(block(), consent(), success(entity=OTHER_SP)) == []


def test_different_service_principal_on_the_block_does_not_correlate():
    assert chains(block(entity=OTHER_SP), consent(), success()) == []


def test_post_consent_success_by_a_different_user_does_not_correlate():
    assert chains(block(), consent(), success(actor=OTHER_USER)) == []


def test_admins_own_success_does_not_stand_in_for_the_requesting_users():
    """Real data: the admin also signs in successfully (same service
    principal) right after granting consent. That is not the requester
    succeeding."""
    assert chains(block(), consent(), success(actor=ADMIN)) == []


def test_consent_outside_the_window_does_not_correlate():
    assert chains(block(), consent(offset=901), success(offset=950)) == []


def test_success_outside_the_window_does_not_correlate():
    """Consent is inside the window but the requester's success is not:
    the WHOLE chain, first step to last, must fit."""
    assert chains(block(), consent(offset=32), success(offset=901)) == []


def test_chain_exactly_at_the_window_boundary_correlates():
    assert len(chains(block(), consent(offset=32), success(offset=900))) == 1


def test_success_before_consent_does_not_correlate():
    assert chains(block(), consent(offset=100), success(offset=50)) == []


def test_consent_before_the_block_does_not_correlate():
    assert chains(block(offset=60), consent(offset=10), success(offset=158)) == []


def test_simultaneous_steps_are_not_strictly_after():
    """Strictly after: a consent stamped the same instant as the block, or a
    success stamped the same instant as the consent, does not count."""
    assert chains(block(0), consent(0), success(158)) == []
    assert chains(block(0), consent(32), success(32)) == []


def test_consent_and_success_without_the_block_do_not_correlate():
    assert chains(consent(), success()) == []


def test_block_and_consent_without_a_success_do_not_correlate():
    assert chains(block(), consent()) == []


def test_block_and_success_without_consent_do_not_correlate():
    assert chains(block(), success()) == []


def test_a_different_first_signal_is_not_the_block():
    """A generic weak-auth/other signal in the first slot must not anchor the
    chain - only admin_consent_required does."""
    generic = sig("weak_auth_session", 0, USER)
    assert chains(generic, consent(), success()) == []


# ---- fail-closed on a missing entity ----

@pytest.mark.parametrize("missing_step", ["block", "consent", "success"])
def test_a_step_with_no_entity_can_never_join_a_chain(missing_step):
    steps = {
        "block": block(entity=None),
        "consent": consent(entity=None),
        "success": success(entity=None),
    }
    ordered = [
        steps["block"] if missing_step == "block" else block(),
        steps["consent"] if missing_step == "consent" else consent(),
        steps["success"] if missing_step == "success" else success(),
    ]
    assert chains(*ordered) == []


def test_two_steps_missing_entity_do_not_match_each_other():
    """None must never equal None: absence of an entity is not a shared
    entity."""
    assert chains(block(entity=None), consent(entity=None), success(entity=None)) == []


# ---- correctness beyond the happy path ----

def test_earlier_consent_for_a_different_entity_does_not_hide_the_right_chain():
    """The case a single global greedy pass gets wrong: the earliest consent
    after the block is for another service principal. Entity filtering must
    happen before the earliest is chosen."""
    result = chains(
        block(),
        consent(offset=20, entity=OTHER_SP),
        consent(offset=40, entity=SP),
        success(offset=158),
    )
    assert len(result) == 1
    assert result[0][1].entity == SP


def test_user_blocked_for_two_service_principals_resolves_the_completed_one():
    result = chains(
        block(offset=0, entity=OTHER_SP),
        block(offset=10, entity=SP),
        consent(offset=60, entity=SP),
        success(offset=120, entity=SP),
    )
    assert len(result) == 1
    assert result[0][0].entity == SP


def test_repeated_blocks_closed_by_one_consent_and_success_are_one_incident():
    result = chains(block(0), block(20), consent(60), success(120))
    assert len(result) == 1
    assert result[0][0].timestamp == T0  # earliest anchor kept


def test_two_independent_requesters_each_get_their_own_chain():
    result = chains(
        block(0, actor=USER), block(5, actor=OTHER_USER),
        consent(30),
        success(100, actor=USER), success(110, actor=OTHER_USER),
    )
    assert {c[0].actor_id for c in result} == {USER, OTHER_USER}
    assert len(result) == 2


def test_simultaneous_consent_signals_pick_deterministically_the_heavier():
    """Two rules can fire on one consent event (real: IDT-ENTRA-001 and
    IDT-ENTRA-002 on the same grant). The choice must be stable."""
    light = sig("risky_oauth_consent", 32, ADMIN, weight=35, event_id="same-event")
    heavy = sig("risky_oauth_consent", 32, ADMIN, weight=45, event_id="same-event")
    for ordering in ([light, heavy], [heavy, light]):
        result = chains(block(), *ordering, success())
        assert result[0][1].weight == 45


def test_evaluate_bridged_rule_wraps_chains_as_hits():
    hits = evaluate_bridged_rule(RULE, [block(), consent(), success()])
    assert len(hits) == 1 and hits[0].rule.id == "IDT-CORR-006"


def test_a_disabled_bridged_rule_never_fires():
    disabled = RULE.model_copy(update={"enabled": False})
    assert evaluate_bridged_rule(disabled, [block(), consent(), success()]) == []


def test_bridged_rule_cannot_be_evaluated_as_a_single_identity_rule():
    with pytest.raises(ValueError, match="entity-bridged"):
        evaluate_correlation_rule(RULE, [block(), consent(), success()])


# ---- the shipped rule is exactly the validated design ----

def test_shipped_rule_is_exactly_the_validated_three_step_design():
    assert RULE.sequence == ["admin_consent_required", "risky_oauth_consent", "new_session_context"]
    assert RULE.actor_binding == ["anchor", "any", "anchor"]
    assert RULE.entity_field == "service_principal_id"
    assert RULE.window_seconds == 900  # unchanged from the existing correlation window
    # Downstream resource access was deliberately NOT made a requirement.
    assert "sensitive_resource_access" not in RULE.sequence


def test_existing_rules_are_not_bridged():
    for rule in load_correlation_rules():
        if rule.id != "IDT-CORR-006":
            assert not rule.is_bridged, f"{rule.id} unexpectedly became entity-bridged"


# ---- schema: unsafe configurations cannot even be loaded ----

def _rule(**overrides):
    base = dict(
        id="T-1", title="t", window_seconds=900, score_bonus=10,
        sequence=["a", "b", "c"],
        actor_binding=["anchor", "any", "anchor"], entity_field="service_principal_id",
    )
    base.update(overrides)
    return CorrelationRule(**base)


def test_valid_bridged_rule_loads():
    assert _rule().is_bridged


def test_cross_identity_without_a_shared_entity_is_rejected():
    """App + time alone is the design the benign data shows to be unsafe."""
    with pytest.raises(ValidationError, match="set together"):
        _rule(entity_field=None)


def test_entity_without_actor_binding_is_rejected():
    with pytest.raises(ValidationError, match="set together"):
        _rule(actor_binding=None)


def test_binding_length_must_match_the_sequence():
    with pytest.raises(ValidationError, match="one entry per sequence step"):
        _rule(actor_binding=["anchor", "anchor"])


def test_first_step_must_be_the_anchor():
    with pytest.raises(ValidationError, match="first step"):
        _rule(actor_binding=["any", "any", "anchor"])


def test_last_step_must_return_to_the_requesting_identity():
    with pytest.raises(ValidationError, match="last step"):
        _rule(actor_binding=["anchor", "anchor", "any"])


def test_entity_field_is_a_closed_set():
    with pytest.raises(ValidationError):
        _rule(entity_field="app_id")


def test_plain_rules_still_need_neither_field():
    plain = CorrelationRule(
        id="T-2", title="t", window_seconds=900, score_bonus=10, sequence=["a", "b"],
    )
    assert not plain.is_bridged


# ---- guards: the rule's signals can only come from the rules it was validated on ----

def _rules_emitting(signal):
    return [r for r in load_rules() if r.signal_name() == signal]


def test_the_block_signal_comes_only_from_idt_entra_007_on_the_narrow_action():
    emitting = _rules_emitting("admin_consent_required")
    assert [r.id for r in emitting] == ["IDT-ENTRA-007"]
    conditions = {(c.field, c.op, c.value) for c in emitting[0].match}
    assert conditions == {("action", "equals", "admin_consent_required")}


def test_the_success_signal_can_only_come_from_a_rule_that_requires_success():
    emitting = _rules_emitting("new_session_context")
    assert emitting, "new_session_context has no producing rule"
    for rule in emitting:
        assert any(
            c.field == "result" and c.op == "equals" and c.value == "success" for c in rule.match
        ), f"{rule.id} emits new_session_context without requiring a successful sign-in"


def test_the_consent_signal_comes_only_from_risky_consent_rules():
    assert {r.id for r in _rules_emitting("risky_oauth_consent")} == {"IDT-ENTRA-001", "IDT-ENTRA-002"}
