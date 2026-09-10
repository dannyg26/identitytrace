import pytest

from app.correlation.scoring import (
    compute_confidence,
    compute_incident_score,
    severity_for_score,
)


@pytest.mark.parametrize(
    "score,expected",
    [(0, "low"), (29, "low"), (30, "medium"), (69, "medium"), (70, "high"),
     (84, "high"), (85, "critical"), (100, "critical")],
)
def test_severity_bands(score, expected):
    assert severity_for_score(score) == expected


def test_incident_score_sums_components():
    assert compute_incident_score(event_risk=30, behavioral_deviation=15, temporal_chain_bonus=20) == 65


def test_incident_score_clamped_to_100():
    assert compute_incident_score(event_risk=80, behavioral_deviation=50, temporal_chain_bonus=40) == 100


def test_incident_score_clamped_to_0():
    assert compute_incident_score(event_risk=-10, behavioral_deviation=0, temporal_chain_bonus=0) == 0


def test_confidence_is_weighted_average_clamped_and_rounded():
    # 0.4*1.0 + 0.3*1.0 + 0.3*1.0 = 1.0
    assert compute_confidence(1.0, 1.0, 1.0) == 1.0
    # 0.4*0 + 0.3*0 + 0.3*0 = 0.0
    assert compute_confidence(0.0, 0.0, 0.0) == 0.0
    assert compute_confidence(0.5, 0.5, 0.5) == 0.5


def test_confidence_out_of_range_inputs_are_clamped():
    assert compute_confidence(2.0, 2.0, 2.0) == 1.0
    assert compute_confidence(-1.0, -1.0, -1.0) == 0.0
