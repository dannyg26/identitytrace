import pytest

from app.correlation.loader import CorrelationLoadError, load_correlation_rules

VALID_RULE = """
id: TEST-CORR-1
title: Test correlation
window_seconds: 600
sequence: [a, b]
score_bonus: 10
"""


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_loads_the_real_shipped_correlation_rules_without_error():
    rules = load_correlation_rules()
    assert len(rules) == 6
    assert len({r.id for r in rules}) == 6


def test_load_valid_rule_from_temp_dir(tmp_path):
    _write(tmp_path, "rule.yaml", VALID_RULE)
    rules = load_correlation_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0].sequence == ["a", "b"]


def test_duplicate_ids_are_rejected(tmp_path):
    _write(tmp_path, "a.yaml", VALID_RULE)
    _write(tmp_path, "b.yaml", VALID_RULE)
    with pytest.raises(CorrelationLoadError, match="duplicate correlation id"):
        load_correlation_rules(tmp_path)


def test_single_step_sequence_is_rejected(tmp_path):
    _write(
        tmp_path,
        "bad.yaml",
        "id: BAD\ntitle: too short\nwindow_seconds: 60\nsequence: [a]\nscore_bonus: 10\n",
    )
    with pytest.raises(CorrelationLoadError, match="invalid correlation rule"):
        load_correlation_rules(tmp_path)


def test_empty_directory_returns_no_rules(tmp_path):
    assert load_correlation_rules(tmp_path) == []
