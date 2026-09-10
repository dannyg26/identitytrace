"""Detection rule schema.

Rules are pure L1 "atomic" detections in the blueprint's four-layer model
(§7): each rule looks only at the fields of a single NormalizedEvent, with
no historical/behavioral context. Deviation-from-baseline checks (L2) and
multi-event sequences (L3/L4) are deliberately out of scope here - they land
in Phase 3 (baselines) and Phase 4 (correlation), which will consume this
engine's output rather than duplicate its logic.

A rule is defined as YAML (see detections/*/*.yaml) and validated into a
DetectionRule via this schema before the engine ever sees it.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# Supported condition operators. Kept as an explicit small set (not a free-form
# expression language) so rules stay data, not code - reviewable, and safe to
# load from YAML without eval().
ConditionOp = Literal[
    "equals",
    "not_equals",
    "in",
    "not_in",
    "any_of",  # event field (a list, e.g. permissions) intersects `values`
    "all_of",  # event field (a list) is a superset of `values`
    "contains",  # substring match on a string field
    "contains_any",  # string field contains at least one of `values` as a substring
    "not_null",  # field is present and non-empty
    "gt",
    "gte",
    "lt",
    "lte",
]


class Condition(BaseModel):
    op: ConditionOp
    field: str
    value: Optional[Any] = None
    values: Optional[list[Any]] = None

    @field_validator("values")
    @classmethod
    def _values_required_for_set_ops(cls, v, info):
        op = info.data.get("op")
        if op in ("in", "not_in", "any_of", "all_of", "contains_any") and not v:
            raise ValueError(f"op '{op}' requires a non-empty 'values' list")
        return v

    @field_validator("value")
    @classmethod
    def _value_required_for_scalar_ops(cls, v, info):
        op = info.data.get("op")
        if op in ("equals", "not_equals", "contains", "gt", "gte", "lt", "lte") and v is None:
            raise ValueError(f"op '{op}' requires a 'value'")
        return v


class AttackMapping(BaseModel):
    id: str  # e.g. "T1550.001"
    name: str  # e.g. "Use Alternate Authentication Material: Application Access Token"


class DetectionRule(BaseModel):
    id: str
    title: str
    description: str = ""
    severity: Severity
    version: int = 1
    enabled: bool = True
    source: Optional[str] = None  # None = applies to events from any source
    event_type: Optional[str] = None  # None = applies to any event_type
    match: list[Condition] = Field(default_factory=list)
    score: int
    attack: list[AttackMapping] = Field(default_factory=list)
    scenario: Optional[str] = None  # attack scenario id this supports, e.g. "A2"
    # The semantic signal name this rule represents for Phase 4 temporal
    # correlation (blueprint §16.2's sequence steps, e.g. "risky_oauth_consent").
    # Several rules can share one signal (e.g. both OAuth-consent rules feed
    # "risky_oauth_consent") so correlation sequences stay short and readable.
    # Defaults to the rule's own id if unset.
    signal: Optional[str] = None

    def signal_name(self) -> str:
        return self.signal or self.id

    @field_validator("score")
    @classmethod
    def _score_in_range(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError("score must be between 0 and 100")
        return v
