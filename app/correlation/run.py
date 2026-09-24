"""Entry point app/api/events.py calls during ingestion: for one identity,
check every loaded correlation rule against its recent signal history and
return the incident payload for each rule that fires.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.correlation.build import build_incident_payload
from app.correlation.engine import evaluate_bridged_rule, evaluate_correlation_rule
from app.correlation.schema import CorrelationRule
from app.correlation.signals import get_signals_for_actor, get_signals_in_window


def run_correlation_for_actor(
    db: Session, actor_id: str, as_of: datetime, rules: list[CorrelationRule]
) -> list[dict]:
    incident_payloads: list[dict] = []
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.is_bridged:
            incident_payloads.extend(_run_bridged_rule(db, rule, as_of))
            continue
        since = as_of - timedelta(seconds=rule.window_seconds)
        signals = get_signals_for_actor(db, actor_id, since=since, until=as_of)
        hit = evaluate_correlation_rule(rule, signals)
        if hit is not None:
            incident_payloads.append(build_incident_payload(db, hit))
    return incident_payloads


def _run_bridged_rule(db: Session, rule: CorrelationRule, as_of: datetime) -> list[dict]:
    """Entity-bridged rules span identities, so they are not scoped to the
    triggering event's actor, and they look FORWARD as well as back.

    Order-independence is deliberate and evidence-based: on real Entra
    telemetry the sign-in and audit logs come from different endpoints and
    propagated at very different speeds (audit events landed minutes before
    the matching sign-ins). Whichever event of the chain happens to arrive
    last must still complete it, so the candidate fetch is [as_of - window,
    as_of + window]; the matcher itself enforces that the actual chain fits
    inside one window. Re-detection is idempotent: the incident id is
    derived from the chain's first event, and upsert_incident preserves any
    analyst triage.
    """
    window = timedelta(seconds=rule.window_seconds)
    signals = get_signals_in_window(
        db,
        since=as_of - window,
        until=as_of + window,
        signal_types=set(rule.sequence),
        entity_field=rule.entity_field,
    )
    return [build_incident_payload(db, hit) for hit in evaluate_bridged_rule(rule, signals)]
