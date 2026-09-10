"""Detection engine: evaluate NormalizedEvents against loaded rules.

Deliberately stateless and side-effect free - it takes an event and a list of
rules and returns matches. Persisting matches, wiring this into the
ingestion path, and exposing it over the API are the caller's job (see
app/api/detections.py), so the engine itself stays trivially unit-testable.
"""

from __future__ import annotations

from typing import Any

from app.detections.schema import Condition, DetectionRule
from app.models.event import NormalizedEvent


class DetectionMatch:
    """One rule firing against one event, with a human-readable reason.

    Design rule (blueprint §7.2): every point of score must be explainable.
    `reasons` is exactly that explanation, not just a pass/fail bit.
    """

    def __init__(self, rule: DetectionRule, event: NormalizedEvent, reasons: list[str]):
        self.rule = rule
        self.event = event
        self.reasons = reasons

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity.value,
            "score": self.rule.score,
            "scenario": self.rule.scenario,
            "signal": self.rule.signal_name(),
            "attack": [a.model_dump() for a in self.rule.attack],
            "event_id": self.event.event_id,
            "actor_id": self.event.actor_id,
            "timestamp": self.event.timestamp,
            "reasons": self.reasons,
        }


def _get_field(event: NormalizedEvent, field: str) -> Any:
    if not hasattr(event, field):
        raise AttributeError(
            f"unknown event field '{field}' referenced in a detection rule"
        )
    return getattr(event, field)


def _describe(field: str, op: str, expected: Any) -> str:
    return f"{field} {op} {expected!r}"


def evaluate_condition(condition: Condition, event: NormalizedEvent) -> tuple[bool, str]:
    """Evaluate one condition. Returns (matched, human_readable_reason)."""
    actual = _get_field(event, condition.field)
    op = condition.op

    if op == "not_null":
        matched = actual is not None and actual != "" and actual != []
        return matched, f"{condition.field} is set (value={actual!r})"

    if op == "equals":
        matched = actual == condition.value
        return matched, _describe(condition.field, "==", condition.value) + f" (actual={actual!r})"

    if op == "not_equals":
        matched = actual != condition.value
        return matched, _describe(condition.field, "!=", condition.value) + f" (actual={actual!r})"

    if op == "in":
        matched = actual in (condition.values or [])
        return matched, f"{condition.field}={actual!r} in {condition.values}"

    if op == "not_in":
        matched = actual not in (condition.values or [])
        return matched, f"{condition.field}={actual!r} not in {condition.values}"

    if op == "contains":
        matched = isinstance(actual, str) and condition.value in actual
        return matched, f"{condition.field}={actual!r} contains {condition.value!r}"

    if op == "contains_any":
        hits = [v for v in (condition.values or []) if isinstance(actual, str) and v in actual]
        matched = bool(hits)
        return matched, f"{condition.field}={actual!r} contains one of {hits or condition.values}"

    if op == "any_of":
        actual_list = actual if isinstance(actual, list) else []
        overlap = sorted(set(actual_list) & set(condition.values or []))
        matched = bool(overlap)
        return matched, f"{condition.field} includes {overlap} (from {condition.values})"

    if op == "all_of":
        actual_list = actual if isinstance(actual, list) else []
        required = set(condition.values or [])
        matched = required.issubset(set(actual_list))
        return matched, f"{condition.field}={actual_list} contains all of {condition.values}"

    if op in ("gt", "gte", "lt", "lte"):
        if actual is None:
            return False, f"{condition.field} is null, cannot compare {op} {condition.value}"
        comparisons = {
            "gt": actual > condition.value,
            "gte": actual >= condition.value,
            "lt": actual < condition.value,
            "lte": actual <= condition.value,
        }
        matched = comparisons[op]
        return matched, f"{condition.field}={actual!r} {op} {condition.value!r}"

    raise ValueError(f"unsupported condition operator: {op!r}")  # pragma: no cover


def rule_applies_to(rule: DetectionRule, event: NormalizedEvent) -> bool:
    if not rule.enabled:
        return False
    if rule.source is not None and event.source != rule.source:
        return False
    if rule.event_type is not None and event.event_type != rule.event_type:
        return False
    return True


def evaluate_rule(rule: DetectionRule, event: NormalizedEvent) -> DetectionMatch | None:
    if not rule_applies_to(rule, event):
        return None

    reasons: list[str] = []
    for condition in rule.match:
        matched, reason = evaluate_condition(condition, event)
        if not matched:
            return None
        reasons.append(reason)

    return DetectionMatch(rule=rule, event=event, reasons=reasons)


def evaluate_event(event: NormalizedEvent, rules: list[DetectionRule]) -> list[DetectionMatch]:
    matches = []
    for rule in rules:
        match = evaluate_rule(rule, event)
        if match is not None:
            matches.append(match)
    return matches
