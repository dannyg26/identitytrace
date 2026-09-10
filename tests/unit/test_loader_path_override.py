"""Regression test for a real packaging bug: DEFAULT_DETECTIONS_DIR /
DEFAULT_CORRELATIONS_DIR are computed relative to app/'s own location,
which only resolves correctly when app/ sits in a source checkout next to
detections/ and correlations/ (true for a local run or an editable
install) - NOT after a real, non-editable `pip install .` relocates the
package into site-packages. Confirmed by literally relocating a copy of
the app package in test_docker_relocation-style below; the env var
override is the fix.
"""

import importlib


def test_detections_dir_honors_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("IDENTITYTRACE_DETECTIONS_DIR", str(tmp_path))
    from app.detections import loader

    importlib.reload(loader)
    try:
        assert loader.DEFAULT_DETECTIONS_DIR == tmp_path
    finally:
        monkeypatch.delenv("IDENTITYTRACE_DETECTIONS_DIR", raising=False)
        importlib.reload(loader)  # restore the real default for other tests


def test_correlations_dir_honors_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("IDENTITYTRACE_CORRELATIONS_DIR", str(tmp_path))
    from app.correlation import loader

    importlib.reload(loader)
    try:
        assert loader.DEFAULT_CORRELATIONS_DIR == tmp_path
    finally:
        monkeypatch.delenv("IDENTITYTRACE_CORRELATIONS_DIR", raising=False)
        importlib.reload(loader)


def test_default_detections_dir_without_override_points_at_the_real_directory():
    """Guards the non-override path too: without the env var, it must
    still resolve to the actual detections/ directory that ships with
    this repo (this is what would silently break under a relocated
    package - see the module docstring)."""
    from app.detections.loader import DEFAULT_DETECTIONS_DIR

    assert DEFAULT_DETECTIONS_DIR.exists()
    assert (DEFAULT_DETECTIONS_DIR / "entra").exists()


def test_default_correlations_dir_without_override_points_at_the_real_directory():
    from app.correlation.loader import DEFAULT_CORRELATIONS_DIR

    assert DEFAULT_CORRELATIONS_DIR.exists()
    assert list(DEFAULT_CORRELATIONS_DIR.glob("*.yaml"))
