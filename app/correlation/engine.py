"""Temporal correlation (blueprint L3): chain signals for one identity,
within a time window, into an ordered sequence match. Pure and stateless -
app/api/events.py wires this into ingestion the same way it wires Phase 2's
rule engine and Phase 3's deviation evaluator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.correlation.schema import CorrelationRule
from app.correlation.signals import SignalOccurrence


@dataclass
class CorrelationHit:
    rule: CorrelationRule
    # One signal per step of rule.sequence, in order - the causal chain.
    matched_signals: list[SignalOccurrence]


def find_chain(
    signals: list[SignalOccurrence], sequence: list[str]
) -> Optional[list[SignalOccurrence]]:
    """Greedy earliest-occurrence subsequence match.

    For each required step in order, take the earliest signal of that type
    at or after the previous step's timestamp. This is a simple, cheap,
    deterministic approximation of "did these things happen in this order" -
    not a general interval-scheduling optimum - but it's exactly what the
    blueprint's own example (§16.2: new_session -> oauth_consent -> ... )
    calls for: an ordered chain, not just co-occurrence.
    """
    matched: list[SignalOccurrence] = []
    floor_time = None
    for step in sequence:
        candidates = [
            s
            for s in signals
            if s.signal_type == step and (floor_time is None or s.timestamp >= floor_time)
        ]
        if not candidates:
            return None
        chosen = min(candidates, key=lambda s: s.timestamp)
        matched.append(chosen)
        floor_time = chosen.timestamp
    return matched


def evaluate_correlation_rule(
    rule: CorrelationRule, signals_in_window: list[SignalOccurrence]
) -> Optional[CorrelationHit]:
    if not rule.enabled:
        return None
    chain = find_chain(signals_in_window, rule.sequence)
    if chain is None:
        return None
    return CorrelationHit(rule=rule, matched_signals=chain)
