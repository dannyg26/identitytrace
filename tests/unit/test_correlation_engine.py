from datetime import datetime, timezone

from app.correlation.engine import evaluate_correlation_rule, find_chain
from app.correlation.schema import CorrelationRule
from app.correlation.signals import SignalOccurrence


def _signal(signal_type, hour, minute=0, kind="detection", weight=10, event_id=None):
    return SignalOccurrence(
        signal_type=signal_type,
        timestamp=datetime(2026, 9, 9, hour, minute, tzinfo=timezone.utc),
        event_id=event_id or f"evt-{signal_type}-{hour}-{minute}",
        actor_id="alice@example.test",
        kind=kind,
        source_id=signal_type,
        weight=weight,
        label=signal_type,
    )


def _rule(**overrides):
    kwargs = dict(
        id="TEST-CORR-1",
        title="test correlation",
        window_seconds=900,
        sequence=["a", "b", "c"],
        score_bonus=20,
    )
    kwargs.update(overrides)
    return CorrelationRule(**kwargs)


def test_chain_found_in_order():
    signals = [_signal("a", 9, 0), _signal("b", 9, 5), _signal("c", 9, 10)]
    chain = find_chain(signals, ["a", "b", "c"])
    assert chain is not None
    assert [s.signal_type for s in chain] == ["a", "b", "c"]


def test_chain_not_found_when_out_of_order():
    # "b" happens before "a" - no valid a->b->c ordering exists.
    signals = [_signal("b", 9, 0), _signal("a", 9, 5), _signal("c", 9, 10)]
    assert find_chain(signals, ["a", "b", "c"]) is None


def test_chain_not_found_when_a_step_is_missing():
    signals = [_signal("a", 9, 0), _signal("c", 9, 10)]  # no "b"
    assert find_chain(signals, ["a", "b", "c"]) is None


def test_chain_picks_earliest_valid_occurrence_per_step():
    signals = [
        _signal("a", 9, 0),
        _signal("b", 9, 30),  # a valid but late "b"
        _signal("b", 9, 5),  # the earlier, correct "b" to use
        _signal("c", 9, 10),
    ]
    chain = find_chain(signals, ["a", "b", "c"])
    assert chain is not None
    assert chain[1].timestamp.minute == 5


def test_same_timestamp_signals_can_satisfy_consecutive_steps():
    # All three signals fired off one single event (same timestamp) -
    # should still satisfy the full chain (>= comparison, not strictly >).
    t = datetime(2026, 9, 9, 9, 0, tzinfo=timezone.utc)
    signals = [
        SignalOccurrence("a", t, "evt-1", "alice@example.test", "detection", "a", 10, "a"),
        SignalOccurrence("b", t, "evt-1", "alice@example.test", "detection", "b", 10, "b"),
        SignalOccurrence("c", t, "evt-1", "alice@example.test", "detection", "c", 10, "c"),
    ]
    chain = find_chain(signals, ["a", "b", "c"])
    assert chain is not None


def test_evaluate_correlation_rule_returns_none_when_disabled():
    rule = _rule(enabled=False)
    signals = [_signal("a", 9, 0), _signal("b", 9, 5), _signal("c", 9, 10)]
    assert evaluate_correlation_rule(rule, signals) is None


def test_evaluate_correlation_rule_returns_hit_with_matched_signals():
    rule = _rule()
    signals = [_signal("a", 9, 0), _signal("b", 9, 5), _signal("c", 9, 10)]
    hit = evaluate_correlation_rule(rule, signals)
    assert hit is not None
    assert hit.rule is rule
    assert len(hit.matched_signals) == 3
