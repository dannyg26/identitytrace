"""Unit tests for the generic condition evaluator and rule matcher -
independent of any specific rule's YAML content (see test_rules.py for
per-rule positive/negative coverage)."""

from datetime import datetime, timezone

import pytest

from app.detections.engine import evaluate_condition, evaluate_rule, rule_applies_to
from app.detections.schema import Condition, DetectionRule
from app.models.event import NormalizedEvent


def _event(**overrides) -> NormalizedEvent:
    kwargs = dict(
        timestamp=datetime(2026, 9, 9, 17, 0, tzinfo=timezone.utc),
        source="entra",
        event_type="signin",
        action="login",
        result="success",
        actor_id="alice@example.test",
        actor_type="user",
    )
    kwargs.update(overrides)
    return NormalizedEvent(**kwargs)


@pytest.mark.parametrize(
    "condition,event_kwargs,expected",
    [
        (Condition(op="equals", field="result", value="success"), {}, True),
        (Condition(op="equals", field="result", value="failure"), {}, False),
        (Condition(op="not_equals", field="result", value="failure"), {}, True),
        (Condition(op="in", field="source", values=["entra", "github"]), {}, True),
        (Condition(op="not_in", field="source", values=["github"]), {}, True),
        (Condition(op="contains", field="action", value="log"), {}, True),
        (Condition(op="contains", field="action", value="zzz"), {}, False),
        (
            Condition(op="contains_any", field="action", values=["zzz", "log"]),
            {},
            True,
        ),
        (
            Condition(op="any_of", field="permissions", values=["offline_access"]),
            {"permissions": ["offline_access", "Mail.Read"]},
            True,
        ),
        (
            Condition(op="any_of", field="permissions", values=["offline_access"]),
            {"permissions": ["Mail.Read"]},
            False,
        ),
        (
            Condition(op="all_of", field="permissions", values=["Mail.Read", "Files.Read.All"]),
            {"permissions": ["Mail.Read", "Files.Read.All", "extra"]},
            True,
        ),
        (
            Condition(op="all_of", field="permissions", values=["Mail.Read", "Files.Read.All"]),
            {"permissions": ["Mail.Read"]},
            False,
        ),
        (Condition(op="not_null", field="device_id"), {"device_id": "d-1"}, True),
        (Condition(op="not_null", field="device_id"), {"device_id": None}, False),
        (Condition(op="gt", field="bytes_transferred", value=100), {"bytes_transferred": 200}, True),
        (Condition(op="gt", field="bytes_transferred", value=100), {"bytes_transferred": 50}, False),
        (Condition(op="gt", field="bytes_transferred", value=100), {"bytes_transferred": None}, False),
        (Condition(op="gte", field="bytes_transferred", value=100), {"bytes_transferred": 100}, True),
        (Condition(op="lt", field="bytes_transferred", value=100), {"bytes_transferred": 50}, True),
        (Condition(op="lte", field="bytes_transferred", value=100), {"bytes_transferred": 100}, True),
    ],
)
def test_condition_ops(condition, event_kwargs, expected):
    matched, reason = evaluate_condition(condition, _event(**event_kwargs))
    assert matched is expected
    assert isinstance(reason, str) and reason  # every condition explains itself


def test_condition_on_unknown_field_raises():
    condition = Condition(op="equals", field="not_a_real_field", value="x")
    with pytest.raises(AttributeError):
        evaluate_condition(condition, _event())


def _rule(**overrides) -> DetectionRule:
    kwargs = dict(
        id="TEST-1",
        title="test rule",
        severity="medium",
        score=10,
        match=[Condition(op="equals", field="result", value="success")],
    )
    kwargs.update(overrides)
    return DetectionRule(**kwargs)


def test_rule_applies_to_respects_source_and_event_type_filters():
    rule = _rule(source="github", event_type="repo_clone")
    assert rule_applies_to(rule, _event(source="github", event_type="repo_clone"))
    assert not rule_applies_to(rule, _event(source="entra", event_type="repo_clone"))
    assert not rule_applies_to(rule, _event(source="github", event_type="signin"))


def test_rule_applies_to_disabled_rule_never_matches():
    rule = _rule(enabled=False)
    assert not rule_applies_to(rule, _event())


def test_evaluate_rule_requires_all_conditions_to_match():
    rule = _rule(
        match=[
            Condition(op="equals", field="result", value="success"),
            Condition(op="equals", field="actor_type", value="service_principal"),
        ]
    )
    assert evaluate_rule(rule, _event(actor_type="user")) is None
    match = evaluate_rule(rule, _event(actor_type="service_principal"))
    assert match is not None
    assert len(match.reasons) == 2


def test_evaluate_rule_records_human_readable_reasons():
    rule = _rule()
    match = evaluate_rule(rule, _event())
    assert match is not None
    assert "result" in match.reasons[0]
    data = match.to_dict()
    assert data["rule_id"] == "TEST-1"
    assert data["reasons"] == match.reasons
