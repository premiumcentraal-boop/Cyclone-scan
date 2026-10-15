"""Run 18: reference deployment configuration, admin separation and config checks."""

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_actions import ADMIN, Env

from device_trust import __version__
from device_trust.api import create_app
from device_trust.cli import main
from device_trust.config_check import check
from device_trust.policy import TrustPolicy
from device_trust.registry import DeviceRegistry

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "deploy" / "reference" / "policy.beta.json"


def _write(path: Path, text: str, mode: int = 0o600) -> str:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)
    return str(path)


@pytest.fixture
def ready(tmp_path):
    """The reference policy with a real-looking signer digest, plus valid secret files."""
    raw = json.loads(REFERENCE.read_text())
    raw.update(signing_cert_sha256=["ab" * 32], package_name="com.bank.app", fleet_hash_key="k" * 32)
    policy = _write(tmp_path / "policy.json", json.dumps(raw))
    return {"policy": policy, "gateway": _write(tmp_path / "gw", "g" * 40), "admin": _write(tmp_path / "ad", "a" * 40)}


def test_reference_policy_is_the_recommended_beta_configuration():
    policy = TrustPolicy.from_file(REFERENCE)
    assert policy.require_principal and policy.require_bound_enrollment and policy.require_bound_device
    assert policy.scan_require_fresh_attestation and policy.policy_version == "beta-1"
    result = check(str(REFERENCE))
    # Shipped with a placeholder signer on purpose: it must not pass until the operator sets it.
    assert not result["ok"] and "signing_cert_sha256" in result["failed"]


def test_ready_beta_configuration_passes(ready):
    result = check(ready["policy"], gateway_token_file=ready["gateway"], admin_token_file=ready["admin"])
    assert result["ok"], result
    assert result["policyDigest"] == TrustPolicy.from_file(ready["policy"]).digest()
    assert "g" * 40 not in json.dumps(result) and "a" * 40 not in json.dumps(result)  # secrets never printed


def test_beta_profile_rejects_development_settings(tmp_path, ready):
    raw = json.loads(Path(ready["policy"]).read_text())
    raw["require_bound_device"] = False
    dev = _write(tmp_path / "dev.json", json.dumps(raw))
    assert "require_bound_device" in check(dev, gateway_token_file=ready["gateway"])["failed"]
    assert check(dev, profile="dev", gateway_token_file=ready["gateway"])["ok"]
    assert "gateway_token" in check(dev, profile="dev")["failed"]  # policy still requires a principal
    # Beta without a gateway token cannot enforce ownership.
    assert "gateway_token" in check(ready["policy"])["failed"]


def test_token_problems(tmp_path, ready):
    short = _write(tmp_path / "short", "x" * 10)
    assert "gateway_token" in check(ready["policy"], gateway_token_file=short)["failed"]
    assert "token_separation" in check(ready["policy"], gateway_token_file=ready["gateway"],
                                       admin_token_file=ready["gateway"])["failed"]
    loose = _write(tmp_path / "loose", "g" * 40, mode=0o644)
    result = check(ready["policy"], gateway_token_file=loose)
    assert result["ok"] and any(c["check"] == "gateway_token" and c["status"] == "WARN" for c in result["checks"])
    assert "gateway_token" in check(ready["policy"], gateway_token_file=str(tmp_path / "missing"))["failed"]


def test_play_configuration(tmp_path, ready):
    raw = json.loads(Path(ready["policy"]).read_text())
    raw["scan_require_play_integrity"] = True
    needs_play = _write(tmp_path / "play.json", json.dumps(raw))
    assert "play_service_account" in check(needs_play, gateway_token_file=ready["gateway"])["failed"]
    bad = _write(tmp_path / "sa.json", json.dumps({"type": "service_account", "client_email": "x"}))
    assert "play_service_account" in check(needs_play, gateway_token_file=ready["gateway"],
                                           play_service_account=bad)["failed"]
    good = _write(tmp_path / "sa2.json", json.dumps({"type": "service_account", "client_email": "x@y",
                                                    "private_key": "-----BEGIN", "token_uri": "https://t"}))
    assert check(needs_play, gateway_token_file=ready["gateway"], play_service_account=good)["ok"]


def test_invalid_policy_fails(tmp_path):
    bad = _write(tmp_path / "bad.json", json.dumps({"package_name": "x", "unknown_key": 1}))
    result = check(bad)
    assert result["failed"] == ["policy"] and result["policyDigest"] is None


def test_check_config_cli_exit_codes(ready, capsys):
    assert main(["check-config", "--policy", ready["policy"], "--gateway-token-file", ready["gateway"]]) == 0
    assert json.loads(capsys.readouterr().out)["ok"]
    assert main(["check-config", "--policy", str(REFERENCE)]) == 1


def test_admin_interface_is_separable(policy):
    env = Env(policy)
    phone = env.phone()
    public = TestClient(create_app(env.service, gateway_token=None))
    assert public.get(f"/v1/admin/devices/{phone.device_id}",
                      headers={"Authorization": f"Bearer {ADMIN}"}).status_code == 404
    admin = TestClient(create_app(env.service, admin_token=ADMIN, public=False))
    assert admin.get(f"/v1/admin/devices/{phone.device_id}",
                     headers={"Authorization": f"Bearer {ADMIN}"}).json()["deviceId"] == phone.device_id
    for path in ("/v1/challenges", "/v1/enrollments", "/v1/actions/verify", "/v1/scans/verify", "/v1/device-challenges"):
        assert admin.post(path, json={}).status_code == 404
    assert admin.get("/healthz").json() == {"status": "ok"}
    assert admin.app.version == __version__
    with pytest.raises(ValueError):
        create_app(env.service, public=False)


def test_file_registry_uses_wal_for_the_shared_admin_process(tmp_path):
    path = tmp_path / "devices.sqlite"
    a, b = DeviceRegistry(path), DeviceRegistry(path)
    assert a._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert b.count() == 0 and DeviceRegistry().count() == 0
