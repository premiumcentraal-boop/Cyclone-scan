"""Run 28: regression tests for the review findings on Runs 17–19.

Each test reproduces a finding that held on the Run 19 head (24b7a71) and
must stay fixed.
"""

import time
from datetime import timedelta

import pytest
from attestation_factory import DEVICE_IDS, KD, NOW, Pki, _cert, _name, chain_der, make_leaf
from cryptography.hazmat.primitives.asymmetric import ec
from test_actions import EchoDecoder, Env
from test_verified_scan import _b64, _sign, device_challenge, rotate, rotation_body, scan, scan_body

from device_trust import reasons as R
from device_trust import scan_evidence
from device_trust.play_integrity import b64url_decode

OTHER_PHONE = {**DEVICE_IDS, "model": "Other Phone", "device": "other", "product": "other"}
OTHER_BOOT_KEY = b"\x07" * 32


def second_keybox(env) -> Pki:
    """Another genuine-looking attestation batch key under the same trusted root (another phone)."""
    key = ec.generate_private_key(ec.SECP256R1())
    inter = _cert(_name("Other Batch Key"), env.pki.root.subject, key.public_key(), env.pki.root_key, ca=True,
                  serial=0x777, not_before=NOW - timedelta(days=30), not_after=NOW + timedelta(days=300))
    return Pki(env.pki.root_key, env.pki.root, key, inter)


def foreign_rotation(env, phone, *, kd_overrides=None, reported=OTHER_PHONE, play=False):
    """The enrolled key signs a rotation to a key attested on a different phone."""
    pki = second_keybox(env)
    ch = device_challenge(env, phone.device_id, "key-rotation").json()
    nonce = b64url_decode(ch["nonce"])
    kd = KD(challenge=nonce, attested_ids=dict(OTHER_PHONE), boot_key=OTHER_BOOT_KEY, **(kd_overrides or {}))
    leaf, key = make_leaf(pki, kd)
    chain = chain_der(leaf, pki.inter, pki.root)
    data = scan_evidence.rotation_data(phone.device_id, ch["challengeId"], nonce, int(time.time() * 1000),
                                       chain, None, reported)
    body = {"deviceId": phone.device_id, "challengeId": ch["challengeId"], "rotationData": _b64(data),
            "oldKeySignature": _sign(phone.device_key, data), "newKeySignature": _sign(key, data),
            "newAttestationChain": [_b64(c) for c in chain]}
    if play:
        body["playIntegrityToken"] = scan_evidence.request_hash("key-rotation", data)
    return body


# --- F1: rotation must not move an enrolled identity to another phone ---------------

def test_rotation_to_a_different_phone_is_refused_and_changes_nothing(policy):
    env = Env(policy)
    phone = env.phone()
    before = env.registry.get(phone.device_id)
    out = rotate(env, foreign_rotation(env, phone))
    assert out["decision"] == "BLOCK" and out["rotated"] is False
    assert R.KEY_ROTATION_DEVICE_CHANGED in out["reasons"]
    after = env.registry.get(phone.device_id)
    assert after.public_key_spki == before.public_key_spki
    # The old key still works; nothing was retired.
    assert env.verify(env.sign(phone))["decision"] == "ALLOW"


@pytest.mark.parametrize("change", [
    {"boot_key": b"\x09" * 32},          # same model, different verified-boot key
    {"os_patch_level": 202601},          # security patch went backwards
])
def test_rotation_with_contradicting_boot_or_patch_evidence_is_refused(policy, change):
    env = Env(policy)
    phone = env.phone()
    ch = device_challenge(env, phone.device_id, "key-rotation").json()
    body, _, _ = rotation_body(env, phone, challenge=ch,
                               kd=KD(challenge=b64url_decode(ch["nonce"]), **change))
    out = rotate(env, body)
    assert out["rotated"] is False and R.KEY_ROTATION_DEVICE_CHANGED in out["reasons"]


def test_same_phone_rotation_still_works_including_an_os_update(policy):
    env = Env(policy)
    phone = env.phone()
    ch = device_challenge(env, phone.device_id, "key-rotation").json()
    body, new_key, _ = rotation_body(env, phone, challenge=ch,
                                     kd=KD(challenge=b64url_decode(ch["nonce"]), os_patch_level=202610,
                                           os_version=140000))
    out = rotate(env, body)
    assert out["decision"] == "ALLOW" and out["rotated"] is True, out


# --- F2: scan baseline and verdict ------------------------------------------------------

def test_scan_with_another_phones_fresh_attestation_is_not_trusted(policy):
    env = Env(policy)
    phone = env.phone()
    ch = device_challenge(env, phone.device_id).json()
    nonce = b64url_decode(ch["nonce"])
    out = scan(env, scan_body(env, phone, challenge=ch, device=OTHER_PHONE,
                              kd=KD(challenge=nonce, attested_ids=dict(OTHER_PHONE), boot_key=OTHER_BOOT_KEY)))
    assert out["decision"] == "STEP_UP"
    assert R.SCAN_DEVICE_EVIDENCE_CHANGED in out["reasons"]
    codes = {c["code"] for c in out["history"]["changes"]}
    assert {"ATTESTED_IDENTITY_CHANGED", "BOOT_EVIDENCE_CHANGED"} <= codes


def test_a_contradicting_scan_does_not_become_the_baseline(policy):
    """Before Run 28 the second scan compared only with the first (foreign) refresh and looked clean."""
    env = Env(policy)
    phone = env.phone()
    for _ in range(2):
        ch = device_challenge(env, phone.device_id).json()
        nonce = b64url_decode(ch["nonce"])
        out = scan(env, scan_body(env, phone, challenge=ch, device=OTHER_PHONE,
                                  kd=KD(challenge=nonce, attested_ids=dict(OTHER_PHONE), boot_key=OTHER_BOOT_KEY)))
        assert out["decision"] == "STEP_UP", out
        assert R.SCAN_DEVICE_EVIDENCE_CHANGED in out["reasons"]


def test_normal_scans_after_an_os_update_stay_allowed(policy):
    env = Env(policy)
    phone = env.phone()
    for patch in (202609, 202610):
        ch = device_challenge(env, phone.device_id).json()
        out = scan(env, scan_body(env, phone, challenge=ch,
                                  kd=KD(challenge=b64url_decode(ch["nonce"]), os_patch_level=patch)))
        assert out["decision"] == "ALLOW", out
        assert not [c for c in out["history"]["changes"] if c["level"] == "REVIEW"]


def test_policy_rejects_unknown_scan_history_mode(policy):
    import dataclasses
    with pytest.raises(ValueError):
        dataclasses.replace(policy, scan_history_review="ignore").validate()


# --- F3: rotation honours require_play_integrity ---------------------------------------

def test_rotation_requires_play_when_enrollment_does(policy):
    env = Env(policy, decoder=EchoDecoder())
    phone = env.phone()
    # Policy tightened after enrollment (or a deployment that always requires Play).
    import dataclasses
    env.service.policy = dataclasses.replace(env.policy, require_play_integrity=True)
    body, _, _ = rotation_body(env, phone)
    out = rotate(env, body)
    assert out["rotated"] is False and R.PLAY_INTEGRITY_MISSING in out["reasons"]


def test_rotation_play_token_must_be_bound_to_the_rotation_transcript(policy):
    import dataclasses
    env = Env(policy, decoder=EchoDecoder())
    phone = env.phone()
    env.service.policy = dataclasses.replace(env.policy, require_play_integrity=True)
    body, _, _ = rotation_body(env, phone)
    data = b64url_decode(body["rotationData"].replace("+", "-").replace("/", "_").rstrip("="))
    # A token minted for a scan of the same bytes is not valid for a rotation.
    body["playIntegrityToken"] = scan_evidence.request_hash("scan", data)
    out = rotate(env, body)
    assert out["rotated"] is False and R.PLAY_INTEGRITY_REQUEST_MISMATCH in out["reasons"]
    body2, _, _ = rotation_body(env, phone)
    data2 = b64url_decode(body2["rotationData"].replace("+", "-").replace("/", "_").rstrip("="))
    body2["playIntegrityToken"] = scan_evidence.request_hash("key-rotation", data2)
    ok = rotate(env, body2)
    assert ok["decision"] == "ALLOW" and ok["rotated"] is True, ok
