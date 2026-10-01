import argparse
from pathlib import Path

import pytest

from scripts.soak_reads import origin, run


@pytest.mark.parametrize("url", ["http://example.com", "https://user:secret@example.com",
                                 "https://example.com/path", "https://example.com?token=secret"])
def test_refuses_unsafe_origin(url):
    with pytest.raises(argparse.ArgumentTypeError):
        origin(url)


def test_missing_credential_stops_without_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Must not send an unauthenticated request")
    monkeypatch.setattr("requests.Session.get", forbidden)
    result = run("https://example.com", Path("missing-soak-token-file"), 60, 4, 2)
    assert result["stopped_early"]
    assert not result["clean_run"]
    assert result["successful_reads"] == 0


def test_denied_authentication_stops_and_does_not_follow_redirects(tmp_path, monkeypatch):
    token = tmp_path / "token"
    token.write_text("test-token")
    class Denied:
        status_code = 401
        def close(self):
            pass
    def deny(*args, **kwargs):
        assert kwargs["allow_redirects"] is False
        return Denied()
    monkeypatch.setattr("requests.Session.get", deny)
    result = run("https://example.com", token, 60, 1, 1)
    assert result["stopped_early"]
    assert result["status_counts"] == {"401": 1}
    assert not result["clean_run"]
