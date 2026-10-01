import json
from uuid import uuid4

import pytest
import yaml

from scripts.onboard_customer import create_bundle


def options():
    return dict(slug="customer-one", tenant_id=str(uuid4()), client_id=str(uuid4()),
                api_id=str(uuid4()), public_url="https://identity.example.test")


def test_customer_bundles_have_separate_secrets_and_networks(tmp_path):
    first = create_bundle(tmp_path, **options())
    second = create_bundle(tmp_path, **{**options(), "slug": "customer-two"})
    one = yaml.safe_load((first / "compose.yml").read_text())
    two = yaml.safe_load((second / "compose.yml").read_text())
    assert one["name"] != two["name"]
    assert "ports" not in one["services"]["postgres"]
    assert "ports" not in one["services"]["app"]
    assert one["services"]["gateway"]["ports"] == ["127.0.0.1:8443:443"]
    assert "db_admin_password" not in one["services"]["app"]["secrets"]
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE" in (first / "init-database.sh").read_text()
    assert b"\r" not in (first / "init-database.sh").read_bytes()
    for name in ("db-password.txt", "db-admin-password.txt", "session-secret.txt"):
        secret = (first / "secrets" / name).read_text()
        assert len(secret) >= 40
        assert secret != (second / "secrets" / name).read_text()
        assert secret not in (first / "compose.yml").read_text()
    assert (first / "secrets/client-secret.txt").read_text() == ""
    public = json.loads((first / "customer.json").read_text())
    env = one["services"]["app"]["environment"]
    assert env["IDENTITYTRACE_ORGANIZATION_ID"] == public["tenant_id"]
    assert env["IDENTITYTRACE_OIDC_SUBJECT_CLAIM"] == "oid"


@pytest.mark.parametrize("changes", [
    {"slug": "../escape"}, {"slug": "Uppercase"}, {"tenant_id": "common"},
    {"public_url": "http://example.test"}, {"public_url": "https://example.test/path"},
    {"public_url": "https://user:password@example.test"},
    {"public_url": "https://example.test:invalid"}, {"https_port": 80},
])
def test_invalid_config_creates_no_bundle(tmp_path, changes):
    with pytest.raises(ValueError):
        create_bundle(tmp_path, **{**options(), **changes})
    assert list(tmp_path.iterdir()) == []


def test_refuses_reuse_and_shared_api_browser_registration(tmp_path):
    config = options()
    create_bundle(tmp_path, **config)
    with pytest.raises(FileExistsError):
        create_bundle(tmp_path, **config)
    with pytest.raises(ValueError, match="separate"):
        create_bundle(tmp_path, **{**options(), "api_id": config["client_id"], "client_id": config["client_id"]})
