import base64
import dataclasses
import logging
import time

import pytest
from attestation_factory import DEVICE_IDS, KD, make_leaf, make_pki, chain_der
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from device_trust import reasons as R
from device_trust.api import create_app
from device_trust.attestation import AttestationVerifier
from device_trust.challenges import ChallengeStore
from device_trust.play_integrity import DecodeError, b64url, b64url_decode, enrollment_request_hash
from device_trust.registry import DeviceRegistry
from device_trust.revocation import RevocationList
from device_trust.roots import RootStore
from device_trust.service import DeviceTrustService
from attestation_factory import PACKAGE, SIGNING_DIGEST


class FakeDecoder:
    """Stands in for Google's decode API; echoes the hash the 'device' sent."""

    def __init__(self, verdicts=("MEETS_DEVICE_INTEGRITY",), fail=False):
        self.verdicts = list(verdicts)
        self.fail = fail

    def decode(self, package_name, token):
        if self.fail:
            raise DecodeError("down")
        return {
            "requestDetails": {"requestPackageName": package_name, "requestHash": token,
                               "timestampMillis": str(int(time.time() * 1000))},
            "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED", "packageName": PACKAGE,
                             "certificateSha256Digest": [b64url(SIGNING_DIGEST)]},
            "deviceIntegrity": {"deviceRecognitionVerdict": self.verdicts},
        }


@pytest.fixture
def pki():
    return make_pki()


def build(policy, pki, *, decoder=None, expose=True, **policy_overrides):
    policy = dataclasses.replace(policy, **policy_overrides)
    service = DeviceTrustService(
        policy,
        AttestationVerifier(policy, RootStore([pki.root]), RevocationList.static({})),
        ChallengeStore(policy.challenge_ttl_seconds),
        DeviceRegistry(),
        decoder,
    )
    return TestClient(create_app(service, expose_reasons=expose)), service


def device_enroll(client, pki, *, kd_overrides=None, device=None, play=False, challenge_id=None):
    """Simulate the phone: get a challenge, attest a key bound to it, enroll."""
    ch = client.post("/v1/challenges")
    assert ch.status_code == 201
    body = ch.json()
    nonce = b64url_decode(body["nonce"])
    leaf, leaf_key = make_leaf(pki, KD(challenge=nonce, **(kd_overrides or {})))
    chain = [base64.b64encode(c).decode() for c in chain_der(leaf, pki.inter, pki.root)]
    req = {"challengeId": challenge_id or body["challengeId"], "attestationChain": chain,
           "device": DEVICE_IDS if device is None else device}
    if play:
        spki = leaf_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        # FakeDecoder echoes the token as the requestHash.
        req["playIntegrityToken"] = enrollment_request_hash(nonce, spki)
    return client.post("/v1/enrollments", json=req), req


def test_genuine_enrollment_is_allowed_and_registered(policy, pki):
    client, service = build(policy, pki)
    resp, _ = device_enroll(client, pki)
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "ALLOW", data
    assert data["deviceId"].startswith("dev_") and data["decisionId"].startswith("dec_")
    stored = service._registry.get(data["deviceId"])
    assert stored["evidence"]["attested_ids"]["model"] == "Pixel 8"
    assert "SERIAL123" not in repr(stored)


def test_challenge_cannot_be_replayed(policy, pki):
    client, _ = build(policy, pki)
    _, req = device_enroll(client, pki)
    replay = client.post("/v1/enrollments", json=req).json()
    assert replay["decision"] == "BLOCK" and replay["reasons"] == [R.CHALLENGE_UNKNOWN]


def test_expired_challenge(policy, pki):
    client, service = build(policy, pki)
    service._challenges._ttl = -1
    resp, _ = device_enroll(client, pki)
    assert resp.json()["reasons"] == [R.CHALLENGE_UNKNOWN]


def test_rooted_device_blocked(policy, pki):
    client, _ = build(policy, pki)
    data = device_enroll(client, pki, kd_overrides={"device_locked": False, "boot_state": 2})[0].json()
    assert data["decision"] == "BLOCK"
    assert {R.BOOTLOADER_UNLOCKED, R.BOOT_STATE_UNVERIFIED} <= set(data["reasons"])
    assert "deviceId" not in data


def test_reasons_hidden_by_default(policy, pki, caplog):
    client, _ = build(policy, pki, expose=False)
    with caplog.at_level(logging.INFO, logger="device_trust.decisions"):
        data = device_enroll(client, pki, kd_overrides={"device_locked": False})[0].json()
    assert data["decision"] == "BLOCK"
    assert "reasons" not in data and "warnings" not in data
    # Operators can still see why, via the decision id.
    assert data["decisionId"] in caplog.text and R.BOOTLOADER_UNLOCKED in caplog.text


def test_spoofed_model_blocked(policy, pki):
    client, _ = build(policy, pki)
    data = device_enroll(client, pki, device=dict(DEVICE_IDS, model="SM-S928B"))[0].json()
    assert data["reasons"] == [R.DEVICE_ID_MISMATCH]


def test_play_integrity_required_but_missing(policy, pki):
    client, _ = build(policy, pki, decoder=FakeDecoder(), require_play_integrity=True)
    assert device_enroll(client, pki)[0].json()["reasons"] == [R.PLAY_INTEGRITY_MISSING]


def test_play_integrity_happy_path(policy, pki):
    client, service = build(policy, pki, decoder=FakeDecoder(), require_play_integrity=True)
    data = device_enroll(client, pki, play=True)[0].json()
    assert data["decision"] == "ALLOW", data
    assert service._registry.get(data["deviceId"])["play_signals"]["device_recognition"] == ["MEETS_DEVICE_INTEGRITY"]


def test_play_token_from_another_key_is_rejected(policy, pki):
    client, _ = build(policy, pki, decoder=FakeDecoder(), require_play_integrity=True)
    ch = client.post("/v1/challenges").json()
    nonce = b64url_decode(ch["nonce"])
    leaf, _ = make_leaf(pki, KD(challenge=nonce))
    req = {"challengeId": ch["challengeId"],
           "attestationChain": [base64.b64encode(c).decode() for c in chain_der(leaf, pki.inter, pki.root)],
           "device": DEVICE_IDS,
           "playIntegrityToken": enrollment_request_hash(nonce, b"some other key")}
    assert client.post("/v1/enrollments", json=req).json()["reasons"] == [R.PLAY_INTEGRITY_REQUEST_MISMATCH]


def test_play_device_integrity_failure_blocks(policy, pki):
    client, _ = build(policy, pki, decoder=FakeDecoder(verdicts=["MEETS_BASIC_INTEGRITY"]))
    data = device_enroll(client, pki, play=True)[0].json()
    assert data["reasons"] == [R.PLAY_DEVICE_INTEGRITY_FAILED]


def test_play_outage_is_warning_when_not_required(policy, pki):
    client, _ = build(policy, pki, decoder=FakeDecoder(fail=True))
    data = device_enroll(client, pki, play=True)[0].json()
    assert data["decision"] == "ALLOW"
    assert data["warnings"] == [R.PLAY_INTEGRITY_UNAVAILABLE]


def test_play_outage_blocks_when_required(policy, pki):
    client, _ = build(policy, pki, decoder=FakeDecoder(fail=True), require_play_integrity=True)
    assert device_enroll(client, pki, play=True)[0].json()["reasons"] == [R.PLAY_INTEGRITY_UNAVAILABLE]


@pytest.mark.parametrize(
    "body",
    [
        {"challengeId": "x", "attestationChain": ["%%%"]},
        {"challengeId": "x", "attestationChain": []},
        {"challengeId": "x", "attestationChain": ["AA=="] * 11},
        {"challengeId": "x", "attestationChain": ["AA=="], "unexpected": 1},
        {"challengeId": "x", "attestationChain": ["A" * 20000]},
    ],
)
def test_invalid_requests_rejected(policy, pki, body):
    client, _ = build(policy, pki)
    assert client.post("/v1/enrollments", json=body).status_code == 422


def test_healthz(policy, pki):
    client, _ = build(policy, pki)
    assert client.get("/healthz").json() == {"status": "ok"}


def test_bundled_roots_reject_test_chain(policy, pki):
    """Sanity check: a self-made chain never passes against the real Google roots."""
    policy2 = policy
    service = DeviceTrustService(
        policy2,
        AttestationVerifier(policy2, RootStore.bundled_google(), RevocationList.static({})),
        ChallengeStore(60),
        DeviceRegistry(),
    )
    client = TestClient(create_app(service, expose_reasons=True))
    assert device_enroll(client, pki)[0].json()["reasons"] == [R.ROOT_UNTRUSTED]
