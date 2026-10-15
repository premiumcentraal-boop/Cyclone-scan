"""Run 19b: open-source licence and the public development signing key (retention: Run 29)."""

import json
import subprocess
from pathlib import Path

import pytest
from test_deployment import _write, ready  # noqa: F401  (fixture)

from device_trust import __version__
from device_trust.config_check import DEV_SIGNER_SHA256, check
from tools.release import check_signing

ROOT = Path(__file__).resolve().parents[2]


def test_apache_license_is_declared_everywhere():
    text = (ROOT / "LICENSE").read_text()
    assert "Apache License" in text and "Version 2.0, January 2004" in text
    assert 'license = "Apache-2.0"' in (ROOT / "service" / "pyproject.toml").read_text()
    assert 'name.set("Apache-2.0")' in (ROOT / "android" / "devicetrust" / "build.gradle.kts").read_text()
    assert "PUBLIC development signing key" in (ROOT / "NOTICE").read_text()
    assert __version__ == "0.9.0.dev1"


def test_dev_signer_digest_matches_the_committed_keystore():
    assert (ROOT / "android" / "signing" / "dev-signer.sha256").read_text().strip() == DEV_SIGNER_SHA256
    assert check_signing.dev_digests() == {DEV_SIGNER_SHA256}
    out = subprocess.run(["keytool", "-list", "-v", "-keystore", str(ROOT / "android/signing/cyclone-dev.jks"),
                          "-storepass", "cyclone-dev"], capture_output=True, text=True)
    if out.returncode != 0:
        pytest.skip("keytool not available")
    line = next(l for l in out.stdout.splitlines() if l.strip().startswith("SHA256:"))
    assert line.split("SHA256:")[1].strip().replace(":", "").lower() == DEV_SIGNER_SHA256
    assert "not for production" in out.stdout


def test_dev_key_is_classified_and_refused_unless_allowed():
    found = [{"sha256": DEV_SIGNER_SHA256, "dn": "CN=Cyclone Scan DEV key", "debug_key": False}]
    result = check_signing.evaluate(found, {DEV_SIGNER_SHA256})
    assert result["identity"] == "DEV_KEY" and not result["ok"]
    assert check_signing.evaluate(found, {DEV_SIGNER_SHA256}, allow_dev=True)["ok"]
    other = [{"sha256": "ab" * 32, "dn": "CN=Bank", "debug_key": False}]
    assert check_signing.evaluate(other, {"ab" * 32})["identity"] == "OTHER_KEY"


def test_beta_profile_rejects_a_policy_trusting_the_public_dev_key(tmp_path, ready):  # noqa: F811
    raw = json.loads(Path(ready["policy"]).read_text())
    raw["signing_cert_sha256"] = [DEV_SIGNER_SHA256]
    dev_policy = _write(tmp_path / "dev.json", json.dumps(raw))
    assert "dev_signing_key" in check(dev_policy, gateway_token_file=ready["gateway"])["failed"]
    result = check(dev_policy, profile="dev", gateway_token_file=ready["gateway"])
    assert result["ok"] and any(c["check"] == "dev_signing_key" and c["status"] == "WARN" for c in result["checks"])
