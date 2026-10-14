"""Run 6: attestation provenance (RKP vs factory keybox), keybox reuse and
hardware-vs-reported consistency checks."""

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from attestation_factory import DEVICE_IDS, KD, NOW, chain_der, make_leaf, make_pki
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from test_actions import Env

from device_trust import reasons as R
from device_trust.attestation import CHAIN_FACTORY, CHAIN_UNRECOGNIZED, CHAIN_RKP, AttestationVerifier, classify_chain
from device_trust.policy import TrustPolicy
from device_trust.revocation import RevocationList
from device_trust.risk import RiskInput, RiskPolicy, assess
from device_trust.roots import RootStore
from device_trust.signals import parse_client_signals

FIXTURES = Path(__file__).parent / "fixtures" / "real"
PIXEL_8 = {"brand": "google", "model": "Pixel 8", "device": "shiba", "product": "shiba", "manufacturer": "Google"}


def real(name):
    return x509.load_pem_x509_certificates((FIXTURES / f"{name}.pem").read_bytes())


# --- chain classification on real Google chains ---------------------------------

@pytest.mark.parametrize(
    "name, expected",
    [
        ("caiman_sdk36_TEE_EC_RKP", CHAIN_RKP),
        ("caiman_sdk36_SB_EC_RKP", CHAIN_RKP),
        ("akita_sdk34_TEE_EC_NONE", CHAIN_RKP),
        ("frankel_sdk37_TEE_EC_2026", CHAIN_RKP),
        ("tegu_sdk36_TEE_EC_2026_ROOT", CHAIN_RKP),
        ("sony-xperia10-iii_sdk33_TEE_EC", CHAIN_FACTORY),
        ("blueline_sdk28_TEE_EC_NONE", CHAIN_FACTORY),
    ],
)
def test_real_chains_are_classified(name, expected):
    assert classify_chain(real(name)) == expected


def _cert(subject_cn, org, issuer: x509.Certificate | None, key, signer, ca=True, days=60):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, org)])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer.subject if issuer else name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=days)))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(signer, hashes.SHA256())


def test_fake_droid_ca_signed_by_a_keybox_is_not_rkp():
    """A leaked keybox can sign a cert *named* Droid CA3, but not in the RKP position."""
    pki = make_pki()  # root -> intermediate ("keybox")
    k3, k_dev = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    fake_ca3 = _cert("Droid CA3", "Google LLC", pki.inter, k3, pki.inter_key)
    dev = _cert("deadbeef", "TEE", fake_ca3, k_dev, k3, days=20)
    leaf, _ = make_leaf(pki, KD())  # leaf content irrelevant here
    chain = [leaf, dev, fake_ca3, pki.inter, pki.root]
    # Run 15: not RKP, and no longer silently called a factory keybox either.
    assert classify_chain(chain) == CHAIN_UNRECOGNIZED


def test_rkp_shape_is_recognised_structurally():
    root_key, k2, k3, kd = (ec.generate_private_key(ec.SECP256R1()) for _ in range(4))
    root = _cert("Root", "Google LLC", None, root_key, root_key)
    ca2 = _cert("Droid CA2", "Google LLC", root, k2, root_key)
    ca3 = _cert("Droid CA3", "Google LLC", ca2, k3, k2)
    dev = _cert("abcd", "TEE", ca3, kd, k3, days=20)
    leaf = _cert("Android Keystore Key", "x", dev, ec.generate_private_key(ec.SECP256R1()), kd, ca=False)
    assert classify_chain([leaf, dev, ca3, ca2, root]) == CHAIN_RKP
    # Same certs, wrong order/length -> not RKP.
    assert classify_chain([leaf, dev, ca2, ca3, root]) == CHAIN_UNRECOGNIZED
    assert classify_chain([leaf, dev, ca3, ca2]) == CHAIN_UNRECOGNIZED


def _verify_real(name, policy):
    certs = real(name)
    exp = json.loads((FIXTURES / f"{name}.json").read_text())
    import base64

    app = exp["softwareEnforced"]["attestationApplicationId"]
    p = dataclasses.replace(policy, package_name=app["packages"][0]["name"],
                            signing_cert_sha256=frozenset(base64.b64decode(s).hex() for s in app["signatures"]),
                            max_os_patch_age_months=1000)
    v = AttestationVerifier(p, RootStore.bundled_google(), RevocationList.static({}))
    hw = exp["hardwareEnforced"]
    reported = {f: hw["attestationId" + f.capitalize()] for f in ("brand", "device", "product", "manufacturer", "model")
                if "attestationId" + f.capitalize() in hw}
    return v.verify([c.public_bytes(Encoding.DER) for c in certs], base64.b64decode(exp["attestationChallenge"]),
                    reported, now=max(c.not_valid_before_utc for c in certs[1:]))


def test_evidence_records_provenance(policy):
    result = _verify_real("caiman_sdk36_TEE_EC_RKP", policy)
    assert result.ok, result.reasons
    assert result.evidence.chain_type == CHAIN_RKP
    assert len(result.evidence.attestation_key_sha256) == 64


def test_require_rkp_policy(policy):
    strict = dataclasses.replace(policy, require_rkp=True)
    assert _verify_real("caiman_sdk36_TEE_EC_RKP", strict).ok
    sony = _verify_real("sony-xperia10-iii_sdk33_TEE_EC", strict)
    assert R.ATTESTATION_NOT_RKP in sony.reasons


# --- risk factors ------------------------------------------------------------------

def factors(evidence, signals=None, reported=None, keybox=None):
    client = parse_client_signals({"v": 1, **(signals or {})})
    return assess(RiskInput(client, None, evidence, reported_ids=reported, keybox=keybox),
                  RiskPolicy(), frozenset(), "login", NOW).factor_names()


BASE = {"os_patch_level": 202609, "vendor_patch_level": 20260905, "boot_patch_level": 20260905,
        "os_version": 160000, "attestation_security_level": "STRONG_BOX"}


def test_factory_chain_on_rkp_only_pixel_is_flagged():
    e = {**BASE, "chain_type": "FACTORY", "attested_ids": {"brand": "google", "model": "Pixel 8"}}
    assert "attestation_not_rkp_on_rkp_model" in factors(e)
    assert "attestation_not_rkp_on_rkp_model" not in factors({**e, "chain_type": "RKP"})


def test_rkp_model_rule_falls_back_to_reported_model():
    e = {**BASE, "chain_type": "FACTORY", "attested_ids": {}}
    assert "attestation_not_rkp_on_rkp_model" in factors(e, reported={"brand": "google", "model": "Pixel 9 Pro"})
    assert "attestation_not_rkp_on_rkp_model" not in factors(e, reported={"brand": "samsung", "model": "SM-S928B"})


def test_factory_keybox_on_modern_os_is_weak_signal():
    e = {**BASE, "chain_type": "FACTORY", "attested_ids": {"brand": "samsung", "model": "SM-S928B"}}
    assert "attestation_factory_keybox_modern_os" in factors(e)
    assert "attestation_factory_keybox_modern_os" not in factors({**e, "os_version": 130000})


@pytest.mark.parametrize(
    "patch, flagged",
    [("2026-09-05", False), ("2026-09-01", False), ("2026-10-05", True), ("2025-09-05", True), ("bad", False), ("", False)],
)
def test_reported_patch_vs_attested(patch, flagged):
    assert ("patch_spoofed" in factors({**BASE, "chain_type": "RKP"}, {"os_security_patch": patch})) is flagged


@pytest.mark.parametrize("release, flagged", [("16", False), ("16.0", False), ("14", True), ("Baklava", False)])
def test_reported_release_vs_attested(release, flagged):
    assert ("os_version_mismatch" in factors({**BASE, "chain_type": "RKP"}, {"os_release": release})) is flagged


def test_patch_level_inconsistency_tolerates_real_world_lag():
    # Real Pixel 3: vendor patch 11 months behind the OS patch -> not flagged.
    assert "patch_level_inconsistent" not in factors(
        {**BASE, "chain_type": "FACTORY", "os_patch_level": 201908, "vendor_patch_level": 201809, "boot_patch_level": 201908})
    assert "patch_level_inconsistent" in factors({**BASE, "chain_type": "RKP", "vendor_patch_level": 20230105})


def test_keybox_stats_factors():
    e = {**BASE, "chain_type": "FACTORY"}
    assert "attestation_key_model_conflict" in factors(e, keybox={"enrollments": 2, "models": ["google/pixel 8", "samsung/sm-s928b"]})
    assert "attestation_key_reuse" in factors(e, keybox={"enrollments": 5, "models": ["samsung/sm-s928b"]})
    assert not {"attestation_key_model_conflict", "attestation_key_reuse"} & set(
        factors(e, keybox={"enrollments": 1, "models": ["samsung/sm-s928b"]}))


def test_policy_loads_provenance_settings():
    p = TrustPolicy.from_dict({"package_name": "p", "signing_cert_sha256": ["ab" * 32], "require_rkp": True,
                               "risk": {"rkp_required_models": ["Google/Pixel 11"], "keybox_reuse_threshold": 3}})
    assert p.require_rkp and "google/pixel 11" in p.risk.rkp_required_models and p.risk.keybox_reuse_threshold == 3


# --- end to end: leaked keybox scenarios -------------------------------------------------

CLEAN = {"v": 1, "app_installer": "com.android.vending", "os_security_patch": "2026-09-05", "os_release": "13"}


def test_leaked_keybox_posing_as_pixel_is_blocked_on_actions(policy):
    env = Env(policy)
    # Synthetic chains have the factory shape; claiming to be a Pixel 8 is the TrickyStore pattern.
    original = dict(DEVICE_IDS)
    DEVICE_IDS.clear(); DEVICE_IDS.update(PIXEL_8)
    try:
        data, phone = env.enroll(signals=CLEAN)
    finally:
        DEVICE_IDS.clear(); DEVICE_IDS.update(original)
    # Enrollment: kept for human review (STEP_UP), not silently allowed.
    assert data["decision"] == "STEP_UP"
    assert {"factor": "attestation_not_rkp_on_rkp_model", "points": 80} in data["risk"]["factors"]
    out = env.verify(env.sign(phone, "payment", overrides={"signals": CLEAN}))
    assert out["decision"] == "BLOCK" and out["reasons"] == [R.RISK_BLOCK]


def test_one_keybox_seen_on_two_models_is_flagged_retroactively(policy):
    env = Env(policy)
    first = env.phone(signals=CLEAN)          # SM-S928B, keybox K
    assert env.verify(env.sign(first, overrides={"signals": CLEAN}))["decision"] == "ALLOW"
    original = dict(DEVICE_IDS)
    DEVICE_IDS.update({"model": "SM-A556B", "device": "a55x"})
    try:
        data, _ = env.enroll(signals=CLEAN)    # same keybox K, different model
    finally:
        DEVICE_IDS.clear(); DEVICE_IDS.update(original)
    assert {"factor": "attestation_key_model_conflict", "points": 80} in data["risk"]["factors"]
    # The first device's next action is now flagged too: the keybox is evidently shared.
    out = env.verify(env.sign(first, overrides={"signals": CLEAN}))
    assert out["decision"] == "BLOCK"
    assert any(f["factor"] == "attestation_key_model_conflict" for f in out["risk"]["factors"])


def test_spoofed_security_patch_props_flagged_end_to_end(policy):
    env = Env(policy)
    phone = env.phone(signals=CLEAN)
    spoofed = {**CLEAN, "os_security_patch": "2026-10-05"}  # attested: 2026-09
    out = env.verify(env.sign(phone, overrides={"signals": spoofed}))
    assert any(f["factor"] == "patch_spoofed" for f in out["risk"]["factors"])
