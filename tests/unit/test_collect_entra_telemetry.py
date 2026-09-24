"""scripts/collect_entra_telemetry.py's only non-trivial pure logic:
normalizing --since/--until into the ISO form Graph's $filter expects.
Requires the real-collection extra (msal, requests) - skipped otherwise,
same as this project's non-dev optional dependencies aren't installed
by default. Install with `pip install -e ".[real-collection]"` to run
this test."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

msal = pytest.importorskip("msal")
pytest.importorskip("requests")

from scripts.collect_entra_telemetry import _iso, scope_without  # noqa: E402


def test_bare_date_gets_midnight_utc():
    assert _iso("2026-09-01") == "2026-09-01T00:00:00Z"


def test_datetime_without_zone_gets_z_appended():
    assert _iso("2026-09-01T12:30:00") == "2026-09-01T12:30:00Z"


def test_datetime_with_z_is_unchanged():
    assert _iso("2026-09-01T12:30:00Z") == "2026-09-01T12:30:00Z"


def test_datetime_with_explicit_offset_is_unchanged():
    assert _iso("2026-09-01T12:30:00+02:00") == "2026-09-01T12:30:00+02:00"


def test_scope_without_removes_only_the_named_scope_and_keeps_order():
    assert scope_without(" openid Mail.Read Mail.ReadWrite offline_access", "Mail.ReadWrite") == "openid Mail.Read offline_access"


def test_scope_without_does_not_remove_a_scope_that_merely_contains_the_name():
    assert scope_without("Mail.Read Mail.ReadWrite", "Mail.Read") == "Mail.ReadWrite"


def test_scope_without_a_missing_scope_is_a_no_op():
    assert scope_without("openid profile", "Mail.ReadWrite") == "openid profile"
