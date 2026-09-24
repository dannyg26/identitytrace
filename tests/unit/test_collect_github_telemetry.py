"""scripts/collect_github_telemetry.py's only non-trivial pure logic:
folding `gh api ... --paginate`'s back-to-back JSON arrays (no
separator) into one flat, untouched list of events."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from scripts.collect_github_telemetry import _parse_paginated_json_arrays  # noqa: E402


def test_single_page():
    text = '[{"id": 1}, {"id": 2}]'
    assert _parse_paginated_json_arrays(text) == [{"id": 1}, {"id": 2}]


def test_multiple_pages_concatenated_with_no_separator():
    text = '[{"id": 1}][{"id": 2}, {"id": 3}]'
    assert _parse_paginated_json_arrays(text) == [{"id": 1}, {"id": 2}, {"id": 3}]


def test_pages_separated_by_whitespace():
    text = '[{"id": 1}]\n[{"id": 2}]'
    assert _parse_paginated_json_arrays(text) == [{"id": 1}, {"id": 2}]


def test_empty_result():
    assert _parse_paginated_json_arrays("") == []
    assert _parse_paginated_json_arrays("   ") == []


def test_empty_array_page_among_pages():
    text = '[][{"id": 1}]'
    assert _parse_paginated_json_arrays(text) == [{"id": 1}]
