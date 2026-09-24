"""Temporal correlation (blueprint L3): chain signals for one identity,
within a time window, into an ordered sequence match. Pure and stateless -
app/api/events.py wires this into ingestion the same way it wires Phase 2's
rule engine and Phase 3's deviation evaluator.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
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


def find_bridged_chains(
    signals: list[SignalOccurrence], rule: CorrelationRule
) -> list[list[SignalOccurrence]]:
    """Entity-bridged chains: the steps may belong to different identities,
    but ONLY where the rule says so (`actor_binding`), and every step must
    reference the exact same non-null shared entity as step 1.

    Built for one real, validated flow (docs/evaluation.md, "A2 End-to-End
    Real Validation"): a requesting user is blocked pending admin consent
    (anchor), an admin grants consent for the same service principal (any
    actor), and the SAME original user then succeeds (anchor again).

    Rules enforced, all fail-closed:
    - the shared entity must be non-null on every step and equal to step 1's
      (an event with no entity can never join a chain - never a wildcard);
    - steps bound to "anchor" must be the same actor as step 1;
    - each step is strictly AFTER the previous one (ties do not count);
    - the whole chain, step 1 to the last step, fits inside window_seconds.

    Unlike find_chain's single global greedy pass, candidates are filtered
    by entity BEFORE the earliest is chosen, per anchor - otherwise an
    earlier consent for a *different* entity would be selected first and
    the valid chain for the right entity would never be found. Choosing the
    earliest qualifying candidate per step is then optimal for existence
    (it leaves the most room for later steps inside the window).

    Returns one chain per completing anchor. Retries (several blocked
    sign-ins by the same user, all closed by the same consent + success)
    collapse into one chain, keeping the earliest anchor.
    """
    assert rule.actor_binding is not None
    sequence, binding = rule.sequence, rule.actor_binding
    window = timedelta(seconds=rule.window_seconds)

    anchors = sorted(
        (s for s in signals if s.signal_type == sequence[0] and s.entity),
        key=lambda s: (s.timestamp, s.event_id),
    )

    chains: list[list[SignalOccurrence]] = []
    seen_tails: set[tuple[str, ...]] = set()
    for anchor in anchors:
        chain = [anchor]
        previous = anchor
        for step, bind in zip(sequence[1:], binding[1:], strict=True):
            candidates = [
                s
                for s in signals
                if s.signal_type == step
                and s.entity == anchor.entity
                and s.timestamp > previous.timestamp
                and s.timestamp - anchor.timestamp <= window
                and (bind == "any" or s.actor_id == anchor.actor_id)
            ]
            if not candidates:
                break
            # Deterministic when several signals share a timestamp (e.g. two
            # rules firing on the same consent event): earliest, then the
            # heaviest, then event_id.
            chosen = min(candidates, key=lambda s: (s.timestamp, -s.weight, s.event_id))
            chain.append(chosen)
            previous = chosen
        else:
            tail = tuple(s.event_id for s in chain[1:])
            if tail not in seen_tails:
                seen_tails.add(tail)
                chains.append(chain)
    return chains


def evaluate_bridged_rule(
    rule: CorrelationRule, signals: list[SignalOccurrence]
) -> list[CorrelationHit]:
    if not rule.enabled:
        return []
    return [CorrelationHit(rule=rule, matched_signals=c) for c in find_bridged_chains(signals, rule)]


def evaluate_correlation_rule(
    rule: CorrelationRule, signals_in_window: list[SignalOccurrence]
) -> Optional[CorrelationHit]:
    if not rule.enabled:
        return None
    if rule.is_bridged:
        # A bridged rule's chain spans identities; feeding it one actor's
        # signals would silently evaluate the wrong (single-identity) thing.
        raise ValueError(
            f"{rule.id} is entity-bridged - use evaluate_bridged_rule() with "
            "signals from all identities"
        )
    chain = find_chain(signals_in_window, rule.sequence)
    if chain is None:
        return None
    return CorrelationHit(rule=rule, matched_signals=chain)
