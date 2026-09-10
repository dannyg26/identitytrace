"""Entry point app/api/events.py calls during ingestion: for one identity,
check every loaded correlation rule against its recent signal history and
return the incident payload for each rule that fires.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.correlation.build import build_incident_payload
from app.correlation.engine import evaluate_correlation_rule
from app.correlation.schema import CorrelationRule
from app.correlation.signals import get_signals_for_actor


def run_correlation_for_actor(
    db: Session, actor_id: str, as_of: datetime, rules: list[CorrelationRule]
) -> list[dict]:
    incident_payloads: list[dict] = []
    for rule in rules:
        if not rule.enabled:
            continue
        since = as_of - timedelta(seconds=rule.window_seconds)
        signals = get_signals_for_actor(db, actor_id, since=since, until=as_of)
        hit = evaluate_correlation_rule(rule, signals)
        if hit is not None:
            incident_payloads.append(build_incident_payload(db, hit))
    return incident_payloads
