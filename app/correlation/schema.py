"""Correlation rule schema (blueprint L3, §7 + the §16.2 reference example,
and §8.3's configurable correlation windows).

A correlation rule looks for an ordered sequence of "signals" - each either
a Phase 2 detection rule's `signal` tag or a Phase 3 `deviation_type` -
occurring for the same identity within a time window. When satisfied, it
produces (or updates) an Incident. See app/correlation/engine.py for the
matcher and app/correlation/build.py for how a match becomes an incident.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from app.baselines.deviation import DEVIATION_TYPES
from app.detections.schema import AttackMapping

# How a step's actor relates to the chain's requesting identity:
#   "anchor" - must be the same actor as step 1 (the original requesting user)
#   "any"    - may be a different actor (e.g. the admin who grants consent)
ActorBinding = Literal["anchor", "any"]

# The only shared entities an entity-bridged rule may link on. Deliberately a
# closed set, not a free-form field name: each one must be justified by real
# telemetry that carries it verbatim on every side of the flow it bridges
# (see docs/evaluation.md, "A2 Cross-Identity Correlation Investigation").
EntityField = Literal["service_principal_id"]

# What a matched chain MEANS.
#   "attack_chain"    - the sequence is itself evidence of the attack it names.
#   "workflow_review" - the sequence is a risky WORKFLOW that legitimate use
#                       produces identically (telemetry cannot tell intent).
#                       It is surfaced for analyst review, never asserted as a
#                       compromise, and its severity is capped unless
#                       independent evidence (`escalation_deviations`) exists.
Classification = Literal["attack_chain", "workflow_review"]

# Highest severity a rule may reach WITHOUT independent escalation evidence.
SeverityCap = Literal["low", "medium", "high"]


class CorrelationRule(BaseModel):
    id: str
    title: str
    description: str = ""
    version: int = 1
    enabled: bool = True
    window_seconds: int
    sequence: list[str]
    score_bonus: int
    scenario: Optional[str] = None
    attack: list[AttackMapping] = Field(default_factory=list)
    # Entity-bridged rules (cross-identity). Both must be set together, or
    # neither - see _validate_bridging.
    actor_binding: Optional[list[ActorBinding]] = None
    entity_field: Optional[EntityField] = None
    # Detection vs. escalation (see Classification). `severity_cap` and
    # `escalation_deviations` are only meaningful for "workflow_review" rules
    # and must be set together with it - see _validate_classification.
    classification: Classification = "attack_chain"
    severity_cap: Optional[SeverityCap] = None
    # Baseline deviation types (Phase 3 `deviation_type`s) that, when present
    # on any of the chain's own events, count as INDEPENDENT evidence: their
    # weights are added to behavioral_deviation and the cap is lifted. Only
    # types the deviation layer can actually produce may be listed.
    escalation_deviations: list[str] = Field(default_factory=list)

    @property
    def is_bridged(self) -> bool:
        return self.actor_binding is not None

    @model_validator(mode="after")
    def _validate_bridging(self) -> "CorrelationRule":
        if self.actor_binding is None and self.entity_field is None:
            return self
        if self.actor_binding is None or self.entity_field is None:
            raise ValueError(
                "actor_binding and entity_field must be set together: an "
                "entity with no actor binding does nothing, and a rule that "
                "lets steps belong to different identities MUST name the "
                "shared entity that links them"
            )
        if len(self.actor_binding) != len(self.sequence):
            raise ValueError(
                "actor_binding must have exactly one entry per sequence step "
                f"({len(self.sequence)}), got {len(self.actor_binding)}"
            )
        if self.actor_binding[0] != "anchor":
            raise ValueError("the first step defines the requesting identity: it must be 'anchor'")
        if self.actor_binding[-1] != "anchor":
            raise ValueError(
                "the last step must return to the requesting identity ('anchor'): "
                "bridging through another identity is only for the middle of the chain"
            )
        return self

    @model_validator(mode="after")
    def _validate_classification(self) -> "CorrelationRule":
        if self.classification == "attack_chain":
            if self.severity_cap is not None or self.escalation_deviations:
                raise ValueError(
                    "severity_cap and escalation_deviations only apply to "
                    "classification 'workflow_review'"
                )
            return self
        if self.severity_cap is None:
            raise ValueError("a 'workflow_review' rule must declare a severity_cap")
        unknown = set(self.escalation_deviations) - DEVIATION_TYPES
        if unknown:
            raise ValueError(
                f"escalation_deviations {sorted(unknown)} are not deviation types the "
                f"baseline layer can produce (known: {sorted(DEVIATION_TYPES)}) - a rule "
                "must not depend on a signal we have no telemetry for"
            )
        return self

    @field_validator("sequence")
    @classmethod
    def _sequence_needs_at_least_two_steps(cls, v: list[str]) -> list[str]:
        if len(v) < 2:
            raise ValueError("a correlation sequence needs at least 2 steps")
        return v

    @field_validator("window_seconds")
    @classmethod
    def _positive_window(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("window_seconds must be positive")
        return v

    @field_validator("score_bonus")
    @classmethod
    def _score_bonus_in_range(cls, v: int) -> int:
        if not (0 <= v <= 100):
            raise ValueError("score_bonus must be between 0 and 100")
        return v
