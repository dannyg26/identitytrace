"""Unit tests for app/pipeline.py's pure normalize_payload() - the
HTTP-free core the API and the evaluation harness both build on. Full
process_event() behavior is already covered end-to-end by the integration
tests (test_event_pipeline.py, test_baselines.py, test_incidents.py),
which now exercise it indirectly through the API.
"""

import pytest
from pydantic import ValidationError

from app.models.event import NormalizedEvent
from app.pipeline import normalize_payload


def test_already_normalized_payload_passes_through():
    event = normalize_payload(
        {
            "timestamp": "2026-09-09T09:00:00Z",
            "source": "synthetic",
            "event_type": "signin",
            "action": "login",
            "result": "success",
            "actor_id": "alice@example.test",
            "actor_type": "user",
        }
    )
    assert isinstance(event, NormalizedEvent)
    assert event.actor_id == "alice@example.test"


def test_raw_envelope_dispatches_to_the_right_normalizer():
    event = normalize_payload(
        {
            "source": "entra",
            "raw": {
                "id": "signin-1",
                "createdDateTime": "2026-09-09T09:00:00Z",
                "userPrincipalName": "alice@example.test",
                "status": {"errorCode": 0},
            },
        }
    )
    assert event.source == "entra"
    assert event.event_type == "signin"


def test_unknown_source_raises_value_error():
    with pytest.raises(ValueError, match="no normalizer registered"):
        normalize_payload({"source": "not_a_real_source", "raw": {}})


def test_malformed_raw_payload_raises_key_error():
    with pytest.raises(KeyError):
        normalize_payload({"source": "entra", "raw": {"id": "x"}})  # missing createdDateTime


def test_invalid_normalized_payload_raises_validation_error():
    with pytest.raises(ValidationError):
        normalize_payload({"source": "synthetic", "event_type": "signin"})  # missing required fields
