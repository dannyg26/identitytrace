import importlib.util
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

spec = importlib.util.spec_from_file_location(
    "azure_startup", Path(__file__).resolve().parents[2] / "infra/azure/startup.py")
startup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(startup)


def settings():
    return {"AZURE_PG_HOST": "test.postgres.database.azure.com",
            "AZURE_APP_DB_PASSWORD": "p@ss:/?&" * 8,
            "AZURE_OIDC_CLIENT_SECRET": "c" * 40,
            "AZURE_SESSION_SECRET": "s" * 48}


def test_secrets_and_database_tls(tmp_path):
    original = settings()
    result = startup.prepare_environment(original, tmp_path)
    url = make_url(result["DATABASE_URL"])
    assert url.password == original["AZURE_APP_DB_PASSWORD"]
    assert url.username == "identitytrace"
    assert url.query["sslmode"] == "verify-full"
    assert url.query["sslrootcert"] == "/etc/ssl/certs/ca-certificates.crt"
    assert not any(key in result for key in ("AZURE_APP_DB_PASSWORD", "AZURE_OIDC_CLIENT_SECRET", "AZURE_SESSION_SECRET"))
    assert Path(result["IDENTITYTRACE_OIDC_CLIENT_SECRET_FILE"]).read_text() == "c" * 40
    assert Path(result["IDENTITYTRACE_SESSION_SECRET_FILE"]).read_text() == "s" * 48
    assert original == settings()


@pytest.mark.parametrize("key,value", [
    ("IDENTITYTRACE_DB_HOST", "other"), ("IDENTITYTRACE_DEMO_MODE", "1"),
    ("AZURE_PG_HOST", "attacker.example"),
    ("AZURE_PG_HOST", "evil/x.postgres.database.azure.com"),
    ("AZURE_APP_DB_PASSWORD", "short"), ("AZURE_SESSION_SECRET", "short"),
])
def test_unsafe_configuration_fails(tmp_path, key, value):
    with pytest.raises(ValueError):
        startup.prepare_environment(settings() | {key: value}, tmp_path)


def test_refuses_to_overwrite_secret(tmp_path):
    (tmp_path / "oidc").write_text("existing")
    with pytest.raises(FileExistsError):
        startup.prepare_environment(settings(), tmp_path)
    assert (tmp_path / "oidc").read_text() == "existing"
