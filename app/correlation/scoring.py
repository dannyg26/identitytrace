"""Incident scoring & confidence (blueprint §7.2):

    incident_score = clamp(
        event_risk + behavioral_deviation + temporal_chain_bonus
        + asset_sensitivity + privilege_context - benign_context_adjustments,
        0, 100
    )
    confidence = evidence_quality * correlation_strength * telemetry_completeness

This project folds `asset_sensitivity` and `privilege_context` into the
Phase 2 rule scores themselves (e.g. IDT-GITHUB-003's "sensitive-named
repo" check already IS an asset-sensitivity signal) rather than modeling
them as separate terms - and doesn't yet implement
`benefit_context_adjustments` (documented false-positive suppression is a
Phase 8 concern). So here: `incident_score = event_risk +
behavioral_deviation + temporal_chain_bonus`, clamped to [0, 100].

`confidence` is a deliberately simple, fully-explainable heuristic - not a
calibrated probability - decomposed the same three ways the blueprint
names:

- `correlation_strength`: how tightly the matched chain clustered in time
  relative to the rule's allowed window (fast = stronger evidence, per the
  blueprint's own thesis about compromise-to-exfiltration speed).
- `evidence_quality`: how distinctive the rule's required sequence is -
  more independent signal types required means a single false positive is
  less likely to satisfy the whole chain by coincidence.
- `telemetry_completeness`: what fraction of the chain's contributing
  events carry raw source evidence (`raw_event_ref`) an analyst can
  actually go inspect.

Every incident's score_breakdown and confidence inputs are stored on the
incident itself (see app/correlation/build.py) so this is never a black
box to the analyst.
"""

from __future__ import annotations

# (score floor, severity label). Blueprint §7.3 defines 5 bands (Low 0-29,
# Suspicious 30-49, Medium 50-69, High 70-84, Critical 85-100); this project
# reuses the 4-level Severity vocabulary already used for detection rules
# (app/detections/schema.py) everywhere else in the UI, collapsing
# "Suspicious" and "Medium" into one "medium" band rather than introducing
# a fifth label used only here.
SEVERITY_BANDS: list[tuple[int, str]] = [
    (85, "critical"),
    (70, "high"),
    (30, "medium"),
    (0, "low"),
]


def severity_for_score(score: int) -> str:
    for floor, label in SEVERITY_BANDS:
        if score >= floor:
            return label
    return "low"  # pragma: no cover - unreachable, floor 0 always matches


def compute_incident_score(
    event_risk: int, behavioral_deviation: int, temporal_chain_bonus: int
) -> int:
    return max(0, min(100, event_risk + behavioral_deviation + temporal_chain_bonus))


def compute_confidence(
    correlation_strength: float, evidence_quality: float, telemetry_completeness: float
) -> float:
    value = (
        0.4 * correlation_strength + 0.3 * evidence_quality + 0.3 * telemetry_completeness
    )
    return round(max(0.0, min(1.0, value)), 2)
