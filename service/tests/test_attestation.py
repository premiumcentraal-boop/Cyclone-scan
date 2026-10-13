import dataclasses
import hashlib
from datetime import timedelta

import pytest
from attestation_factory import (
    BOOT_KEY,
    DEVICE_IDS,
    KD,
    NOW,
    chain_der,
    kd_extension,
    make_chain,
    make_leaf,
    make_pki,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from device_trust import reasons as R
from device_trust.attestation import AttestationVerifier, patch_age_months
from device_trust.revocation import RevocationList
from device_trust.roots import RootStore

CHALLENGE = b"challenge"


def verify(policy, chain, pki, *, revocations=None, reported=DEVICE_IDS, challenge=CHALLENGE, now=NOW, roots=None):
    verifier = AttestationVerifier(
        policy,
        roots if roots is not None else RootStore([pki.root]),
        revocations if revocations is not None else RevocationList.static({}),
    )
    return verifier.verify(chain, challenge, reported, now=now)


def test_genuine_device_passes(policy):
    chain, pki, _ = make_chain()
    result = verify(policy, chain, pki)
    assert result.ok, result.reasons
    ev = result.evidence
    assert ev.attestation_security_level == "TRUSTED_ENVIRONMENT"
    assert ev.device_locked is True and ev.verified_boot_state == "VERIFIED"
    assert ev.os_patch_level == 202609
    assert ev.attested_ids == DEVICE_IDS
    assert result.leaf_public_key_spki


def test_serial_and_imei_are_never_exposed(policy):
    chain, pki, _ = make_chain()
    result = verify(policy, chain, pki)
    text = repr(dataclasses.asdict(result.evidence))
    assert "SERIAL123" not in text and "359999999999999" not in text


@pytest.mark.parametrize(
    "kd, reason",
    [
        (KD(challenge=b"other"), R.CHALLENGE_MISMATCH),
        (KD(device_locked=False), R.BOOTLOADER_UNLOCKED),
        (KD(boot_state=2), R.BOOT_STATE_UNVERIFIED),
        (KD(boot_state=3), R.BOOT_STATE_UNVERIFIED),
        (KD(boot_state=1), R.BOOT_STATE_SELF_SIGNED),
        (KD(security_level=0, keymint_security_level=0), R.SECURITY_LEVEL_TOO_LOW),
        (KD(keymint_security_level=0), R.SECURITY_LEVEL_TOO_LOW),
        (KD(origin=2), R.KEY_NOT_HARDWARE_GENERATED),
        (KD(include_root_of_trust=False), R.ROOT_OF_TRUST_MISSING),
        (KD(include_app_id=False), R.APP_ID_MISSING),
        (KD(package="com.evil.clone"), R.PACKAGE_MISMATCH),
        (KD(signing_digests=[hashlib.sha256(b"resigned").digest()]), R.SIGNING_CERT_MISMATCH),
        (KD(signing_digests=[]), R.SIGNING_CERT_MISMATCH),
        (KD(os_patch_level=202401), R.OS_PATCH_TOO_OLD),
        (KD(os_patch_level=0), R.OS_PATCH_UNKNOWN),
    ],
)
def test_attestation_content_failures(policy, kd, reason):
    chain, pki, _ = make_chain(kd)
    result = verify(policy, chain, pki)
    assert reason in result.reasons


def test_strongbox_requirement(policy):
    strict = dataclasses.replace(policy, min_security_level=2)
    chain, pki, _ = make_chain(KD(security_level=1))
    assert R.SECURITY_LEVEL_TOO_LOW in verify(strict, chain, pki).reasons
    chain, pki, _ = make_chain(KD(security_level=2, keymint_security_level=2))
    assert verify(strict, chain, pki).ok


def test_self_signed_custom_os_allowed_when_key_allowlisted(policy):
    allowed = dataclasses.replace(policy, allowed_self_signed_boot_keys=frozenset({hashlib.sha256(BOOT_KEY).hexdigest()}))
    chain, pki, _ = make_chain(KD(boot_state=1))
    assert verify(allowed, chain, pki).ok
    # Still requires a locked bootloader.
    chain, pki, _ = make_chain(KD(boot_state=1, device_locked=False))
    assert R.BOOTLOADER_UNLOCKED in verify(allowed, chain, pki).reasons


def test_patch_level_formats():
    assert patch_age_months(202609, NOW) == 1
    assert patch_age_months(20260905, NOW) == 1
    with pytest.raises(ValueError):
        patch_age_months(202613, NOW)


def test_untrusted_root(policy):
    chain, pki, _ = make_chain()
    other = make_pki(root_cn="Attacker Root")
    result = verify(policy, chain, pki, roots=RootStore([other.root]))
    assert result.reasons == (R.ROOT_UNTRUSTED,)


def test_self_made_chain_with_same_root_name_rejected(policy):
    real = make_pki()
    fake = make_pki()  # same CN, different key
    leaf, _ = make_leaf(fake, KD())
    result = verify(policy, chain_der(leaf, fake.inter, fake.root), real)
    assert result.reasons == (R.ROOT_UNTRUSTED,)


def test_broken_chain_signature(policy):
    pki = make_pki()
    other = make_pki()
    leaf, _ = make_leaf(other, KD())  # issued by other's intermediate
    result = verify(policy, chain_der(leaf, pki.inter, pki.root), pki)
    assert result.reasons == (R.CHAIN_SIGNATURE_INVALID,)


def test_forged_leaf_signed_by_attested_key_is_rejected(policy):
    """Attacker takes a genuine attested key and uses it to sign a fake leaf."""
    pki = make_pki()
    genuine_leaf, genuine_key = make_leaf(pki, KD(device_locked=True))
    from cryptography.hazmat.primitives.asymmetric import ec

    fake_key = ec.generate_private_key(ec.SECP256R1())
    forged = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(genuine_leaf.subject)
        .public_key(fake_key.public_key())
        .serial_number(7)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(kd_extension(KD(challenge=b"attacker-chosen").encode()), critical=False)
        .sign(genuine_key, hashes.SHA256())
    )
    result = verify(policy, chain_der(forged, genuine_leaf, pki.inter, pki.root), pki,
                    challenge=b"attacker-chosen")
    assert result.reasons == (R.ATTESTATION_EXTENSION_MISPLACED,)


def test_missing_extension(policy):
    pki = make_pki()
    leaf, _ = make_leaf(pki, None)
    assert verify(policy, chain_der(leaf, pki.inter, pki.root), pki).reasons == (R.ATTESTATION_EXTENSION_MISSING,)


def test_malformed_extension(policy):
    pki = make_pki()
    leaf, _ = make_leaf(pki, b"\x30\x03\x02\x01")
    result = verify(policy, chain_der(leaf, pki.inter, pki.root), pki)
    assert R.ATTESTATION_EXTENSION_MALFORMED in result.reasons


@pytest.mark.parametrize("chain", [[], [b"not a cert"], [b"\x30\x00"] * 11])
def test_malformed_chain(policy, chain):
    _, pki, _ = make_chain()
    assert verify(policy, chain, pki).reasons == (R.CHAIN_MALFORMED,)


def test_single_cert_chain_rejected(policy):
    chain, pki, _ = make_chain()
    assert verify(policy, chain[:1], pki).reasons == (R.CHAIN_MALFORMED,)


def test_revoked_intermediate(policy):
    pki = make_pki(inter_serial=0x1F4363F4ACEF)
    chain, _, _ = make_chain(pki=pki)
    revoked = RevocationList.static({"1f4363f4acef": {"status": "REVOKED", "reason": "KEY_COMPROMISE"}})
    assert R.CERT_REVOKED in verify(policy, chain, pki, revocations=revoked).reasons


def test_revoked_serial_matching_is_case_and_padding_insensitive(policy):
    pki = make_pki(inter_serial=0x0ABC)
    chain, _, _ = make_chain(pki=pki)
    revoked = RevocationList.static({"0ABC": {"status": "REVOKED"}})
    assert R.CERT_REVOKED in verify(policy, chain, pki, revocations=revoked).reasons


def test_revocation_unavailable_fails_closed(policy):
    chain, pki, _ = make_chain()

    def boom(_url):
        raise OSError("network down")

    rl = RevocationList(fetch=boom)
    assert R.REVOCATION_UNAVAILABLE in verify(policy, chain, pki, revocations=rl).reasons


def test_expired_intermediate(policy):
    pki = make_pki(inter_not_after=NOW - timedelta(days=2))
    chain, _, _ = make_chain(pki=pki)
    assert R.CERT_EXPIRED in verify(policy, chain, pki).reasons


def test_device_identity_mismatch(policy):
    chain, pki, _ = make_chain()
    spoofed = dict(DEVICE_IDS, model="Pixel 9 Pro")
    result = verify(policy, chain, pki, reported=spoofed)
    assert R.DEVICE_ID_MISMATCH in result.reasons
    assert result.evidence.mismatched_ids == ("model",)


def test_hidden_build_fields_count_as_mismatch(policy):
    chain, pki, _ = make_chain()
    assert R.DEVICE_ID_MISMATCH in verify(policy, chain, pki, reported={}).reasons


def test_device_without_id_attestation_is_not_penalised(policy):
    chain, pki, _ = make_chain(KD(attested_ids={}))
    assert verify(policy, chain, pki, reported={"model": "Anything"}).ok


def test_bundled_google_roots_load():
    store = RootStore.bundled_google()
    assert len(store) >= 2
