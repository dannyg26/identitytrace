"""Correlation rule schema (blueprint L3, §7 + the §16.2 reference example,
and §8.3's configurable correlation windows).

A correlation rule looks for an ordered sequence of "signals" - each either
a Phase 2 detection rule's `signal` tag or a Phase 3 `deviation_type` -
occurring for the same identity within a time window. When satisfied, it
produces (or updates) an Incident. See app/correlation/engine.py for the
matcher and app/correlation/build.py for how a match becomes an incident.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.detections.schema import AttackMapping


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
