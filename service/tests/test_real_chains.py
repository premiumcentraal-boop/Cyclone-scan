"""Regression tests against real device attestation chains (see fixtures/real/NOTICE.md)."""

import base64
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from device_trust import reasons as R
from device_trust.attestation import AttestationVerifier
from device_trust.policy import TrustPolicy
from device_trust.revocation import RevocationList
from device_trust.roots import RootStore

FIXTURES = Path(__file__).parent / "fixtures" / "real"
ID_FIELDS = ("brand", "device", "product", "manufacturer", "model")


def load(name: str):
    certs = x509.load_pem_x509_certificates((FIXTURES / f"{name}.pem").read_bytes())
    exp_path = FIXTURES / f"{name}.json"
    return certs, (json.loads(exp_path.read_text()) if exp_path.exists() else None)


def run(name: str, *, reported_overrides=None):
    certs, exp = load(name)
    if exp:
        app = exp["softwareEnforced"]["attestationApplicationId"]
        challenge = base64.b64decode(exp["attestationChallenge"])
        package = app["packages"][0]["name"]
        digests = frozenset(base64.b64decode(s).hex() for s in app["signatures"])
        hw = exp["hardwareEnforced"]
        reported = {f: hw["attestationId" + f.capitalize()] for f in ID_FIELDS if "attestationId" + f.capitalize() in hw}
    else:
        challenge, package, digests, reported = b"", "unused", frozenset({"00" * 32}), {}
    reported.update(reported_overrides or {})
    # Patch age is judged at the time the fixture was captured, not today.
    policy = TrustPolicy(package_name=package, signing_cert_sha256=digests, max_os_patch_age_months=12)
    verifier = AttestationVerifier(policy, RootStore.bundled_google(), RevocationList.static({}))
    now = max(c.not_valid_before_utc for c in certs[1:])
    return verifier.verify([c.public_bytes(Encoding.DER) for c in certs], challenge, reported, now=now), exp


@pytest.mark.parametrize(
    "name",
    ["caiman_sdk36_TEE_EC_RKP", "caiman_sdk36_SB_EC_RKP", "frankel_sdk37_TEE_EC_2026", "sony-xperia10-iii_sdk33_TEE_EC"],
)
def test_genuine_locked_devices_pass(name):
    result, exp = run(name)
    assert result.ok, result.reasons
    ev, hw = result.evidence, exp["hardwareEnforced"]
    assert ev.attestation_security_level == exp["attestationSecurityLevel"]
    assert ev.verified_boot_state == hw["rootOfTrust"]["verifiedBootState"]
    assert str(ev.os_patch_level) == hw["osPatchLevel"]
    for f in ID_FIELDS:
        key = "attestationId" + f.capitalize()
        if key in hw:
            assert ev.attested_ids[f] == hw[key]


def test_strongbox_chain_reports_strongbox():
    result, _ = run("caiman_sdk36_SB_EC_RKP")
    assert result.evidence.attestation_security_level == "STRONG_BOX"


def test_spoofed_model_on_real_device_is_caught():
    result, _ = run("caiman_sdk36_TEE_EC_RKP", reported_overrides={"model": "Pixel 10 Pro"})
    assert result.reasons == (R.DEVICE_ID_MISMATCH,)


def test_unlocked_dev_device_blocked():
    result, _ = run("akita_sdk34_TEE_EC_NONE")
    assert {R.BOOTLOADER_UNLOCKED, R.BOOT_STATE_UNVERIFIED} <= set(result.reasons)


def test_software_attestation_root_untrusted():
    result, _ = run("marlin_sdk29_TEE_EC_NONE")
    assert result.reasons == (R.ROOT_UNTRUSTED,)


def test_non_der_boolean_in_root_of_trust_rejected():
    result, _ = run("invalid_malformed_rot_device_locked")
    assert R.ATTESTATION_EXTENSION_MALFORMED in result.reasons


def test_revoked_real_intermediate_blocked():
    certs, _ = load("caiman_sdk36_TEE_EC_RKP")
    serial = format(certs[1].serial_number, "x")
    policy = TrustPolicy(package_name="x", signing_cert_sha256=frozenset({"00" * 32}))
    verifier = AttestationVerifier(policy, RootStore.bundled_google(),
                                   RevocationList.static({serial: {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}))
    now = max(c.not_valid_before_utc for c in certs[1:])
    result = verifier.verify([c.public_bytes(Encoding.DER) for c in certs], b"", {}, now=now)
    assert R.CERT_REVOKED in result.reasons
