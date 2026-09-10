"""Compute the blueprint's required evaluation metrics (§10.3) from a
completed evaluation run's database - comparing the isolated-rule baseline
(every Phase 2 atomic match, treated as its own alert) against the full
correlation engine (Phase 4 incidents), which is this project's actual
research question (§2.1): does correlation improve precision and reduce
analyst alert volume versus isolated rules alone?
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.evaluation.scenarios import ScenarioInstance
from app.models.detection import DetectionMatchRecord
from app.models.incident import IncidentRecord


def _avg(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 1) if values else None


def _aware(dt: datetime) -> datetime:
    """SQLite round-trips DateTime(timezone=True) columns as naive
    datetimes regardless of what was stored - assume UTC (everything in
    this app is stored/compared in UTC) rather than let a naive/aware
    subtraction blow up."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def compute_metrics(
    db: Session,
    scenarios: list[ScenarioInstance],
    malicious_event_ids: set[str],
    benign_event_ids: set[str],
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

    return {
        "totals": {
            "attack_scenarios": len(scenarios),
            "benign_events": len(benign_event_ids),
            "malicious_events": len(malicious_event_ids),
            "atomic_alerts": len(all_matches),
            "incidents": len(all_incidents),
        },
        "isolated_rule_baseline": {
            "recall": round(recall_isolated, 3),
            "precision": round(precision_isolated, 3) if precision_isolated is not None else None,
            "false_positive_alerts": len(fp_alerts),
            "false_positive_rate": round(fp_rate_isolated, 3) if fp_rate_isolated is not None else None,
            "avg_detection_latency_seconds": _avg(
                [p["latency_isolated_seconds"] for p in per_scenario if p["latency_isolated_seconds"] is not None]
            ),
        },
        "correlation_engine": {
            "recall": round(recall_correlated, 3),
            "precision": round(precision_correlated, 3) if precision_correlated is not None else None,
            "false_positive_incidents": len(fp_incidents),
            "avg_detection_latency_seconds": _avg(
                [p["latency_correlated_seconds"] for p in per_scenario if p["latency_correlated_seconds"] is not None]
            ),
        },
        "alert_reduction_ratio": alert_reduction_ratio,
        "scenario_coverage": scenario_coverage,
        "per_scenario": per_scenario,
    }
