"""Compute the blueprint's required evaluation metrics (§10.3, extended by
Phase 9 #12: F1, a proper correlation-layer false-positive *rate*) from a
completed evaluation run's database - comparing the isolated-rule baseline
(every Phase 2 atomic match, treated as its own alert) against the full
correlation engine (Phase 4 incidents), which is this project's actual
research question: does correlation improve precision and reduce analyst
alert volume versus isolated rules alone, while distinguishing malicious
identity chains from isolated legitimate events more effectively than
atomic rules alone?
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.evaluation.scenarios import BenignSequence, ScenarioInstance
from app.models.detection import DetectionMatchRecord
from app.models.incident import IncidentRecord


def _avg(values: list[float]) -> Optional[float]:
    return round(sum(values) / len(values), 1) if values else None


def _aware(dt: datetime) -> datetime:
    """SQLite round-trips DateTime(timezone=True) columns as naive
    datetimes regardless of what was stored - assume UTC (everything in
    this app is stored/compared in UTC) rather than let a naive/aware
    subtraction blow up."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _f1(precision: Optional[float], recall: Optional[float]) -> Optional[float]:
    if precision is None or recall is None or (precision + recall) == 0:
        return None
    return round(2 * precision * recall / (precision + recall), 3)


def compute_metrics(
    db: Session,
    scenarios: list[ScenarioInstance],
    malicious_event_ids: set[str],
    benign_event_ids: set[str],
    benign_sequences: Optional[list[BenignSequence]] = None,
) -> dict:
    all_matches = db.query(DetectionMatchRecord).all()
    all_incidents = db.query(IncidentRecord).all()

    tp_alerts = [m for m in all_matches if m.event_id in malicious_event_ids]
    fp_alerts = [m for m in all_matches if m.event_id in benign_event_ids]

    tp_incidents = [i for i in all_incidents if set(i.evidence_ids) & malicious_event_ids]
    fp_incidents = [
        i for i in all_incidents
        if i.evidence_ids and not (set(i.evidence_ids) & malicious_event_ids)
    ]

    per_scenario = []
    for scenario in scenarios:
        mal_ids = scenario.malicious_event_ids
        matched_alerts = [m for m in all_matches if m.event_id in mal_ids]
        matched_incidents = [i for i in all_incidents if set(i.evidence_ids) & mal_ids]

        start_time = _aware(scenario.start_time)

        latency_isolated = None
        if matched_alerts:
            earliest = _aware(min(m.timestamp for m in matched_alerts))
            latency_isolated = (earliest - start_time).total_seconds()

        latency_correlated = None
        if matched_incidents:
            earliest = _aware(min(i.last_event_at for i in matched_incidents))
            latency_correlated = (earliest - start_time).total_seconds()

        per_scenario.append({
            "scenario_id": scenario.scenario_id,
            "attack_type": scenario.attack_type,
            "detected_isolated_rule": bool(matched_alerts),
            "detected_correlation": bool(matched_incidents),
            "latency_isolated_seconds": latency_isolated,
            "latency_correlated_seconds": latency_correlated,
        })

    n_scenarios = len(scenarios) or 1
    recall_isolated = sum(p["detected_isolated_rule"] for p in per_scenario) / n_scenarios
    recall_correlated = sum(p["detected_correlation"] for p in per_scenario) / n_scenarios

    precision_isolated = len(tp_alerts) / len(all_matches) if all_matches else None
    precision_correlated = len(tp_incidents) / len(all_incidents) if all_incidents else None

    fp_rate_isolated = len(fp_alerts) / len(benign_event_ids) if benign_event_ids else None
    # The correlation layer's false-positive rate needs a denominator that
    # means something at the identity/activity level, not the raw event
    # level (one incident spans several events; "per event" isn't the
    # right unit to ask "how often did this false-alarm"). Phase 9 #12:
    # rate = false-positive incidents / benign *sequences* (one persona's
    # full activity = one trial), falling back to None if the caller
    # didn't pass sequences (e.g. a hand-built metrics test).
    fp_rate_correlated = (
        len(fp_incidents) / len(benign_sequences) if benign_sequences else None
    )

    alert_reduction_ratio = (
        round(len(all_matches) / len(all_incidents), 2) if all_incidents else None
    )

    by_type: dict[str, list[dict]] = {}
    for p in per_scenario:
        by_type.setdefault(p["attack_type"], []).append(p)
    scenario_coverage = {
        attack_type: {
            "instances": len(items),
            "recall_isolated": round(sum(i["detected_isolated_rule"] for i in items) / len(items), 2),
            "recall_correlated": round(sum(i["detected_correlation"] for i in items) / len(items), 2),
        }
        for attack_type, items in sorted(by_type.items())
    }

    precision_isolated_r = round(precision_isolated, 3) if precision_isolated is not None else None
    precision_correlated_r = round(precision_correlated, 3) if precision_correlated is not None else None
    recall_isolated_r = round(recall_isolated, 3)
    recall_correlated_r = round(recall_correlated, 3)

    return {
        "totals": {
            "attack_scenarios": len(scenarios),
            "benign_events": len(benign_event_ids),
            "benign_sequences": len(benign_sequences) if benign_sequences else None,
            "malicious_events": len(malicious_event_ids),
            "atomic_alerts": len(all_matches),
            "incidents": len(all_incidents),
        },
        "isolated_rule_baseline": {
            "recall": recall_isolated_r,
            "precision": precision_isolated_r,
            "f1": _f1(precision_isolated_r, recall_isolated_r),
            "false_positive_alerts": len(fp_alerts),
            "false_positive_rate": round(fp_rate_isolated, 3) if fp_rate_isolated is not None else None,
            "avg_detection_latency_seconds": _avg(
                [p["latency_isolated_seconds"] for p in per_scenario if p["latency_isolated_seconds"] is not None]
            ),
        },
        "correlation_engine": {
            "recall": recall_correlated_r,
            "precision": precision_correlated_r,
            "f1": _f1(precision_correlated_r, recall_correlated_r),
            "false_positive_incidents": len(fp_incidents),
            "false_positive_rate": round(fp_rate_correlated, 3) if fp_rate_correlated is not None else None,
            "avg_detection_latency_seconds": _avg(
                [p["latency_correlated_seconds"] for p in per_scenario if p["latency_correlated_seconds"] is not None]
            ),
        },
        "alert_reduction_ratio": alert_reduction_ratio,
        "scenario_coverage": scenario_coverage,
        "per_scenario": per_scenario,
    }
