"""Run 15: verifier compatibility with Google's attestation guidance.

Fixtures are Google's public test chains (fixtures/real/NOTICE.md) and
synthetic chains; no customer evidence or private key material.
"""

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from attestation_factory import DEVICE_IDS, KD, NOW, Pki, _cert, chain_der, make_leaf
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from device_trust import reasons as R
from device_trust.attestation import (
    CHAIN_FACTORY,
    CHAIN_RKP,
    CHAIN_UNRECOGNIZED,
    PROVISIONING_INFO_OID,
    AttestationVerifier,
    chain_security_claim,
    classify_chain,
    security_level_matches_chain,
)
from device_trust.policy import TrustPolicy
from device_trust.revocation import RevocationList
from device_trust.roots import RootStore, spki_der

FIXTURES = Path(__file__).parent / "fixtures" / "real"
# A fixed "today" after the legacy factory certificates in the fixtures expired.
TODAY = datetime(2026, 10, 14, tzinfo=timezone.utc)


def real(name):
    certs = x509.load_pem_x509_certificates((FIXTURES / f"{name}.pem").read_bytes())
    exp = json.loads((FIXTURES / f"{name}.json").read_text())
    return certs, exp


def verify_real(name, now, **policy_overrides):
    certs, exp = real(name)
    app = exp["softwareEnforced"]["attestationApplicationId"]
    hw = exp["hardwareEnforced"]
    reported = {f: hw["attestationId" + f.capitalize()] for f in ("brand", "device", "product", "manufacturer", "model")
                if "attestationId" + f.capitalize() in hw}
    revocations = policy_overrides.pop("revocations", None)
    policy = TrustPolicy(package_name=app["packages"][0]["name"],
                         signing_cert_sha256=frozenset(base64.b64decode(s).hex() for s in app["signatures"]),
                         max_os_patch_age_months=1000, **policy_overrides)
    v = AttestationVerifier(policy, RootStore.bundled_google(), revocations or RevocationList.static({}))
    return v.verify([c.public_bytes(Encoding.DER) for c in certs],
                    base64.b64decode(exp["attestationChallenge"]), reported, now=now)


@pytest.mark.parametrize("name,expected", [
    ("akita_sdk34_TEE_EC_NONE", CHAIN_RKP),
    ("caiman_sdk36_TEE_EC_RKP", CHAIN_RKP),
    ("caiman_sdk36_SB_EC_RKP", CHAIN_RKP),
    ("frankel_sdk37_TEE_EC_2026", CHAIN_RKP),
    ("sony-xperia10-iii_sdk33_TEE_EC", CHAIN_FACTORY),
    ("blueline_sdk28_TEE_EC_NONE", CHAIN_FACTORY),
])
def test_official_chain_forms_are_classified(name, expected):
    assert classify_chain(real(name)[0]) == expected


def test_tegu_2026_root_chain_is_rkp():
    certs = x509.load_pem_x509_certificates((FIXTURES / "tegu_sdk36_TEE_EC_2026_ROOT.pem").read_bytes())
    assert classify_chain(certs) == CHAIN_RKP


def test_legacy_factory_chain_with_expired_certs_is_accepted_as_google_documents():
    result = verify_real("sony-xperia10-iii_sdk33_TEE_EC", TODAY)
    assert result.ok, result.reasons
    assert result.evidence.chain_type == CHAIN_FACTORY
    assert result.evidence.legacy_validity_exemption is True
    assert result.notes == (R.LEGACY_FACTORY_VALIDITY_EXEMPT,)


def test_legacy_exemption_can_be_turned_off():
    result = verify_real("sony-xperia10-iii_sdk33_TEE_EC", TODAY, legacy_factory_validity_exemption=False)
    assert R.CERT_EXPIRED in result.reasons


def test_in_date_factory_chain_needs_no_exemption():
    certs, _ = real("sony-xperia10-iii_sdk33_TEE_EC")
    result = verify_real("sony-xperia10-iii_sdk33_TEE_EC", max(c.not_valid_before_utc for c in certs[1:]))
    assert result.ok and result.notes == () and result.evidence.legacy_validity_exemption is False


def test_expired_rkp_chain_is_still_rejected():
    result = verify_real("caiman_sdk36_TEE_EC_RKP", TODAY)
    assert R.CERT_EXPIRED in result.reasons
    assert result.evidence.legacy_validity_exemption is False


def test_not_yet_valid_is_never_exempt():
    certs, _ = real("sony-xperia10-iii_sdk33_TEE_EC")
    result = verify_real("sony-xperia10-iii_sdk33_TEE_EC", min(c.not_valid_before_utc for c in certs[1:]) - timedelta(days=30))
    assert R.CERT_EXPIRED in result.reasons


def test_revoked_legacy_factory_chain_still_fails():
    certs, _ = real("sony-xperia10-iii_sdk33_TEE_EC")
    revoked = RevocationList.static({format(certs[1].serial_number, "x"): {"status": "REVOKED"}})
    result = verify_real("sony-xperia10-iii_sdk33_TEE_EC", TODAY, revocations=revoked)
    assert R.CERT_REVOKED in result.reasons


def test_enrolled_key_is_the_attested_leaf_key():
    certs, _ = real("caiman_sdk36_TEE_EC_RKP")
    result = verify_real("caiman_sdk36_TEE_EC_RKP", max(c.not_valid_before_utc for c in certs[1:]))
    assert result.ok, result.reasons
    assert result.leaf_public_key_spki == spki_der(certs[0])


# --- synthetic chains ---------------------------------------------------------

def _named(**attrs):
    oids = {"cn": NameOID.COMMON_NAME, "o": NameOID.ORGANIZATION_NAME, "serial": NameOID.SERIAL_NUMBER,
            "title": NameOID.TITLE}
    return x509.Name([x509.NameAttribute(oids[k], v) for k, v in attrs.items()])


def factory_pki(*, factory_after=None, root_serial="0123456789abcdef", title="TEE"):
    """root -> factory intermediate (serialNumber) -> attestation key; caller adds the leaf."""
    root_key, fac_key, att_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _cert(_named(serial=root_serial), _named(serial=root_serial), root_key.public_key(), root_key, ca=True,
                 serial=10, not_before=NOW - timedelta(days=3650), not_after=NOW + timedelta(days=3650))
    fac = _cert(_named(title=title, serial="aa11"), root.subject, fac_key.public_key(), root_key, ca=True, serial=11,
                not_before=NOW - timedelta(days=3000), not_after=factory_after or NOW + timedelta(days=365))
    att = _cert(_named(title=title, serial="bb22"), fac.subject, att_key.public_key(), fac_key, ca=True, serial=12,
                not_before=NOW - timedelta(days=3000), not_after=NOW + timedelta(days=365))
    return root, fac, Pki(root_key, root, att_key, att)


def run(policy, certs, root, *, kd_challenge=b"challenge"):
    v = AttestationVerifier(policy, RootStore([root]), RevocationList.static({}))
    return v.verify(chain_der(*certs), kd_challenge, DEVICE_IDS, now=NOW)


def test_synthetic_four_cert_factory_chain_is_factory(policy):
    root, fac, pki = factory_pki()
    leaf, _ = make_leaf(pki, KD())
    result = run(policy, [leaf, pki.inter, fac, root], root)
    assert result.ok, result.reasons
    assert result.evidence.chain_type == CHAIN_FACTORY and result.notes == ()


def test_exemption_needs_googles_legacy_root(policy):
    """An expired factory chain under any other root (even a trusted one) is not exempt."""
    root, fac, pki = factory_pki(factory_after=NOW - timedelta(days=10))
    leaf, _ = make_leaf(pki, KD())
    result = run(policy, [leaf, pki.inter, fac, root], root)
    assert R.CERT_EXPIRED in result.reasons


def test_exemption_applies_only_to_the_factory_form(policy):
    root, fac, pki = factory_pki(root_serial="f92009e853b6b045", factory_after=NOW - timedelta(days=10))
    leaf, _ = make_leaf(pki, KD())
    ok = run(policy, [leaf, pki.inter, fac, root], root)
    assert ok.ok, ok.reasons
    assert ok.notes == (R.LEGACY_FACTORY_VALIDITY_EXEMPT,)
    # Same expired intermediate in an unrecognized (3-certificate) shape: enforced.
    short_root, short_fac, short_pki = factory_pki(root_serial="f92009e853b6b045")
    expired_att = _cert(_named(serial="cc33"), short_root.subject, short_pki.inter_key.public_key(), short_pki.root_key,
                        ca=True, serial=13, not_before=NOW - timedelta(days=3000), not_after=NOW - timedelta(days=1))
    leaf3, _ = make_leaf(Pki(short_pki.root_key, short_root, short_pki.inter_key, expired_att), KD())
    bad = run(policy, [leaf3, expired_att, short_root], short_root)
    assert R.CERT_EXPIRED in bad.reasons
    assert R.ATTESTATION_CHAIN_UNRECOGNIZED in bad.notes


def test_strongbox_claim_must_match_chain(policy):
    root, fac, pki = factory_pki(title="TEE")
    leaf, _ = make_leaf(pki, KD(security_level=2, keymint_security_level=2))  # claims StrongBox
    result = run(policy, [leaf, pki.inter, fac, root], root)
    assert R.SECURITY_LEVEL_CHAIN_MISMATCH in result.reasons
    root2, fac2, pki2 = factory_pki(title="StrongBox")
    leaf2, _ = make_leaf(pki2, KD(security_level=2, keymint_security_level=2))
    assert run(policy, [leaf2, pki2.inter, fac2, root2], root2).ok


def test_provisioning_info_must_sit_above_the_leaf(policy):
    root, fac, pki = factory_pki()
    info = x509.UnrecognizedExtension(x509.ObjectIdentifier(PROVISIONING_INFO_OID), b"\xa0\x00")
    fac_with_info = _cert(fac.subject, root.subject, fac.public_key(), pki.root_key, ca=True, serial=21,
                          not_before=fac.not_valid_before_utc, not_after=fac.not_valid_after_utc, extensions=[info])
    leaf, _ = make_leaf(pki, KD())
    result = run(policy, [leaf, pki.inter, fac_with_info, root], root)
    assert result.reasons == (R.PROVISIONING_INFO_MISPLACED,)


def test_second_key_description_is_rejected_as_attest_key_or_forgery(policy):
    root, fac, pki = factory_pki()
    leaf, leaf_key = make_leaf(pki, KD())
    fake = _cert(_named(cn="Android Keystore Key"), leaf.subject, ec.generate_private_key(ec.SECP256R1()).public_key(),
                 leaf_key, ca=False, serial=99, not_before=NOW - timedelta(days=1), not_after=NOW + timedelta(days=1),
                 extensions=[leaf.extensions.get_extension_for_oid(
                     x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")).value])
    result = run(policy, [fake, leaf, pki.inter, fac, root], root)
    assert result.reasons == (R.ATTESTATION_EXTENSION_MISPLACED,)


@pytest.mark.parametrize("keymint,claim,ok", [
    ("STRONG_BOX", "STRONG_BOX", True), ("STRONG_BOX", None, False), ("STRONG_BOX", "TRUSTED_ENVIRONMENT", False),
    ("TRUSTED_ENVIRONMENT", None, True), ("TRUSTED_ENVIRONMENT", "TRUSTED_ENVIRONMENT", True),
    ("TRUSTED_ENVIRONMENT", "STRONG_BOX", False), ("SOFTWARE", None, True), ("SOFTWARE", "TRUSTED_ENVIRONMENT", False),
])
def test_security_level_rule_matches_reference(keymint, claim, ok):
    assert security_level_matches_chain(keymint, claim) is ok


def test_rkp_claims_come_from_the_attestation_cert():
    assert chain_security_claim(real("caiman_sdk36_SB_EC_RKP")[0], CHAIN_RKP) == "STRONG_BOX"
    assert chain_security_claim(real("caiman_sdk36_TEE_EC_RKP")[0], CHAIN_RKP) == "TRUSTED_ENVIRONMENT"
    assert chain_security_claim(real("sony-xperia10-iii_sdk33_TEE_EC")[0], CHAIN_FACTORY) is None


def test_bundled_roots_are_the_two_documented_google_roots():
    roots = RootStore.bundled_google()
    subjects = sorted(c.subject.rfc4514_string() for c in roots._by_spki.values())
    assert len(roots) == 2
    assert any("f92009e853b6b045" in s for s in subjects)
    assert any("Key Attestation CA1" in s for s in subjects)


def test_unrecognized_chain_keeps_not_rkp_risk_factors():
    """Scores stay as before Run 15: an unrecognized shape is still 'not RKP'."""
    from device_trust.risk import RiskInput, RiskPolicy, assess

    ev = {"os_patch_level": 202609, "attestation_security_level": "TRUSTED_ENVIRONMENT", "os_version": 160000,
          "attested_ids": {"brand": "google", "model": "Pixel 9"}}
    f = lambda ct: assess(RiskInput(None, None, {**ev, "chain_type": ct}), RiskPolicy(), frozenset(), None, TODAY).factors
    assert f(CHAIN_UNRECOGNIZED) == f(CHAIN_FACTORY)
    assert "attestation_not_rkp_on_rkp_model" not in dict(f(CHAIN_RKP))
