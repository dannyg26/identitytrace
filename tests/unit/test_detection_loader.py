import pytest

from app.detections.loader import DetectionLoadError, load_rules

VALID_RULE = """
id: TEST-RULE-1
title: Test rule
severity: low
source: entra
match:
  - op: equals
    field: result
    value: success
score: 10
"""


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_loads_the_real_shipped_rule_set_without_error():
    rules = load_rules()
    assert len(rules) == 13
    assert len({r.id for r in rules}) == 13  # all ids unique


def test_load_valid_rule_from_temp_dir(tmp_path):
    _write(tmp_path, "rule.yaml", VALID_RULE)
    rules = load_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0].id == "TEST-RULE-1"


def test_duplicate_ids_are_rejected(tmp_path):
    _write(tmp_path, "a.yaml", VALID_RULE)
    _write(tmp_path, "b.yaml", VALID_RULE)  # same id
    with pytest.raises(DetectionLoadError, match="duplicate detection id"):
        load_rules(tmp_path)


def test_invalid_rule_yaml_is_rejected(tmp_path):
    _write(tmp_path, "bad.yaml", "id: BAD\ntitle: missing severity and score\n")
    with pytest.raises(DetectionLoadError, match="invalid detection rule"):
        load_rules(tmp_path)


def test_empty_directory_returns_no_rules(tmp_path):
    assert load_rules(tmp_path) == []
