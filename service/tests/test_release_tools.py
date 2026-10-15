"""Run 18: signer allowlist check and build evidence (offline; apksigner faked)."""

import json
import stat
from pathlib import Path

import pytest

from tools.release import build_evidence, check_signing

ROOT = Path(__file__).resolve().parents[2]
DEBUG_OUT = """Signer #1 certificate DN: C=US, O=Android, CN=Android Debug
Signer #1 certificate SHA-256 digest: 64abdca3a6cd0f43b5ef2a12507524434c230b7b8ab68d7795c9814e5ddbeb12
Signer #1 certificate SHA-1 digest: 6337444e03aab9a83623e09672519086f0f6c4e0
"""
RELEASE_OUT = """Signer #1 certificate DN: CN=Example Bank Release
Signer #1 certificate SHA-256 digest: AB""" + "ab" * 31 + "\n"


def fake_apksigner(tmp_path, output, code=0):
    script = tmp_path / "apksigner"
    script.write_text(f"#!/bin/sh\ncat <<'X'\n{output}X\nexit {code}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def test_parse_and_classify_signers():
    debug = check_signing.parse_apksigner(DEBUG_OUT)
    assert debug == [{"sha256": "64abdca3a6cd0f43b5ef2a12507524434c230b7b8ab68d7795c9814e5ddbeb12",
                      "dn": check_signing.DEBUG_DN, "debug_key": True}]
    release = check_signing.parse_apksigner(RELEASE_OUT)
    assert release[0]["sha256"] == "ab" * 32 and not release[0]["debug_key"]
    with pytest.raises(ValueError):
        check_signing.parse_apksigner("nothing here")


def test_evaluate_requires_allowlist_and_rejects_debug_by_default():
    release = check_signing.parse_apksigner(RELEASE_OUT)
    assert check_signing.evaluate(release, {"ab" * 32})["ok"]
    assert not check_signing.evaluate(release, {"cd" * 32})["ok"]
    debug = check_signing.parse_apksigner(DEBUG_OUT)
    allowed = {debug[0]["sha256"]}
    assert not check_signing.evaluate(debug, allowed)["ok"]
    assert check_signing.evaluate(debug, allowed, allow_debug=True)["identity"] == "TEST_DEBUG_KEY"


def test_check_signing_cli(tmp_path, capsys):
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"apk")
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"signing_cert_sha256": ["AB:" + ":".join(["ab"] * 31)]}))
    tool = fake_apksigner(tmp_path, RELEASE_OUT)
    assert check_signing.main([str(apk), "--policy", str(policy), "--apksigner", tool]) == 0
    assert json.loads(capsys.readouterr().out)["allowed_by_policy"]
    broken = fake_apksigner(tmp_path, "", code=1)
    with pytest.raises(SystemExit) as exit_info:
        check_signing.main([str(apk), "--policy", str(policy), "--apksigner", broken])
    assert exit_info.value.code == 2


def test_toolchain_matches_the_build_files():
    tc = build_evidence.toolchain(ROOT / "android")
    assert tc["ndk"] == "27.2.12479018" and tc["cmake"] == "3.22.1" and tc["compile_sdk"] == "35"
    assert tc["version"] == "0.9.0-beta.1" and tc["version_code"] == "6"
    assert tc["gradle"] and tc["android_gradle_plugin"] and tc["kotlin"]


def test_evidence_records_reproducibility_and_signer(tmp_path):
    aar1, aar2, apk = tmp_path / "1.aar", tmp_path / "2.aar", tmp_path / "s.apk"
    aar1.write_bytes(b"same")
    aar2.write_bytes(b"same")
    apk.write_bytes(b"apk")
    rev = "a" * 40
    tool = fake_apksigner(tmp_path, DEBUG_OUT)
    out = build_evidence.evidence(rev, str(ROOT / "android"), str(aar1), str(apk), str(aar2), apksigner=tool, java="17")
    assert out["aar_reproducible"] is True and out["signing"]["identity"] == "TEST_DEBUG_KEY"
    aar2.write_bytes(b"different")
    assert build_evidence.evidence(rev, str(ROOT / "android"), str(aar1), str(apk), str(aar2),
                                   apksigner=tool, java="17")["aar_reproducible"] is False
    unverified = build_evidence.evidence(rev, str(ROOT / "android"), str(aar1), str(apk),
                                         apksigner=str(tmp_path / "missing"), java="17")
    assert unverified["signing"]["identity"] == "UNVERIFIED" and unverified["aar_reproducible"] is None
    with pytest.raises(ValueError):
        build_evidence.evidence("HEAD", str(ROOT / "android"), str(aar1), str(apk))
    with pytest.raises(ValueError):
        build_evidence.evidence(rev, str(ROOT / "android"), str(tmp_path / "none.aar"), str(apk))
