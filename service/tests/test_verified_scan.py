"""Run 17: server-verified scan, fresh attestation, key rotation and history."""

import base64
import dataclasses
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from attestation_factory import DEVICE_IDS, KD, chain_der, make_leaf
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from test_actions import BIOMETRIC, EchoDecoder, Env
from test_lifecycle import STEP_UP_SIGNALS, AsPrincipal, act_as, gateway_env

from device_trust import reasons as R
from device_trust import registry as registry_module
from device_trust import scan_evidence
from device_trust.evidence_history import compare_continuity
from device_trust.play_integrity import DecodeError, b64url, b64url_decode
from device_trust.registry import DeviceRegistry, SchemaVersionError
from device_trust.service import ScanRequest

CLEAN_SIGNALS = {"v": 1, "env_in_call": False}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _sign(key, data: bytes) -> str:
    return _b64(key.sign(data, ec.ECDSA(hashes.SHA256())))


def device_challenge(env, device_id, purpose="scan"):
    return env.client.post("/v1/device-challenges", json={"deviceId": device_id, "purpose": purpose})


def scan_body(env, phone, *, fresh=True, kd=None, leaf_key=None, signals=CLEAN_SIGNALS, ts=None, signer=None,
              challenge=None, device=None, play=False, data=None, chain=None, digests_chain=None):
    """A scan as the SDK builds it: ephemeral fresh key, transcript signed by the enrolled key."""
    ch = challenge or device_challenge(env, phone.device_id).json()
    nonce = b64url_decode(ch["nonce"])
    if fresh and chain is None:
        leaf, _ = make_leaf(env.pki, kd or KD(challenge=nonce), leaf_key=leaf_key)
        chain = chain_der(leaf, env.pki.inter, env.pki.root)
    if data is None:
        data = scan_evidence.scan_data(phone.device_id, ch["challengeId"], nonce,
                                       int(time.time() * 1000) if ts is None else ts,
                                       digests_chain if digests_chain is not None else chain,
                                       DEVICE_IDS if device is None else device, signals)
    body = {"deviceId": phone.device_id, "challengeId": ch["challengeId"], "scanData": _b64(data),
            "signature": _sign(signer or phone.device_key, data)}
    if chain:
        body["freshAttestationChain"] = [_b64(c) for c in chain]
    if play:
        body["playIntegrityToken"] = scan_evidence.request_hash("scan", data)
    return body


def scan(env, body):
    return env.client.post("/v1/scans/verify", json=body).json()


def rotation_body(env, phone, *, confirm=False, old_signer=None, new_signer=None, kd=None, challenge=None,
                  new_key=None):
    ch = challenge or device_challenge(env, phone.device_id, "key-rotation").json()
    nonce = b64url_decode(ch["nonce"])
    leaf, key = make_leaf(env.pki, kd or KD(challenge=nonce), leaf_key=new_key)
    chain = chain_der(leaf, env.pki.inter, env.pki.root)
    cchain = ckey = None
    if confirm:
        cleaf, ckey = make_leaf(env.pki, KD(challenge=nonce, **BIOMETRIC))
        cchain = chain_der(cleaf, env.pki.inter, env.pki.root)
    data = scan_evidence.rotation_data(phone.device_id, ch["challengeId"], nonce, int(time.time() * 1000),
                                       chain, cchain, DEVICE_IDS)
    body = {"deviceId": phone.device_id, "challengeId": ch["challengeId"], "rotationData": _b64(data),
            "oldKeySignature": _sign(old_signer or phone.device_key, data),
            "newKeySignature": _sign(new_signer or key, data),
            "newAttestationChain": [_b64(c) for c in chain]}
    if cchain:
        body["newConfirmKeyChain"] = [_b64(c) for c in cchain]
    return body, key, ckey


def rotate(env, body):
    return env.client.post("/v1/key-rotations", json=body).json()


@pytest.fixture
def env(policy):
    return Env(policy, policy_version="beta-test")


# --- happy path and result contract ---------------------------------------------

def test_verified_scan_with_fresh_attestation(env):
    phone = env.phone()
    out = scan(env, scan_body(env, phone))
    assert out["decision"] == "ALLOW", out
    assert out["evidence"] == {"deviceKeySignature": "VERIFIED", "freshAttestation": "VERIFIED",
                               "playIntegrity": "NOT_PROVIDED", "clientSignals": "SIGNED"}
    assert out["policy"] == {"version": "beta-test", "digest": env.policy.digest(),
                             "verifierRuleset": "run15-attestation-v1"}
    assert out["freshUntil"] - out["verifiedAt"] == env.policy.scan_result_ttl_seconds * 1000
    assert abs(out["verifiedAt"] - time.time() * 1000) < 60_000
    assert out["coverage"] is not None
    history = out["history"]
    assert history["compared"] and history["snapshots"] == 2 and history["previousSource"] == "enrollment"
    assert history["changes"][0] == {"code": "FRESH_KEY_AUTHORIZED", "level": "INFO", "field": "leaf_spki_sha256"}
    assert not [c for c in history["changes"] if c["level"] == "REVIEW"]
    # Logged as a scan decision; never as an action (velocity) or an enrollment (keybox history).
    kinds = [d["kind"] for d in env.registry.decisions_for(phone.device_id)]
    assert kinds.count("scan") == 1
    assert env.registry.count_recent_actions(phone.device_id, 3600) == 0


def test_snapshot_is_minimal_and_never_holds_reported_fields(env):
    phone = env.phone()
    scan(env, scan_body(env, phone, device={**DEVICE_IDS}))
    latest = env.registry.assurance_history(phone.device_id, 1)[0]["evidence"]
    assert latest["source"] == "scan_refresh"
    assert latest["device_key_sha256"] != latest["leaf_spki_sha256"]
    assert not {"signals", "device", "reported_ids", "play_integrity_token", "client_ip", "serial", "imei"} & set(latest)


def test_reasons_and_risk_hidden_without_expose_reasons(policy):
    from fastapi.testclient import TestClient
    from device_trust.api import create_app
    env = Env(policy)
    phone = env.phone()
    env.client = TestClient(create_app(env.service))
    out = scan(env, scan_body(env, phone))
    assert out["decision"] == "ALLOW"
    assert not {"reasons", "warnings", "risk"} & set(out)
    assert "evidence" in out and "history" in out


def test_scan_never_changes_lifecycle_or_key(env):
    phone = env.phone()
    before = env.registry.get(phone.device_id)
    scan(env, scan_body(env, phone))
    after = env.registry.get(phone.device_id)
    assert (after.status, after.public_key_spki, after.state_changed_at) == \
           (before.status, before.public_key_spki, before.state_changed_at)
    assert env.verify(env.sign(phone))["decision"] == "ALLOW"


# --- replay, binding, wrong key -----------------------------------------------------

def test_replay_is_refused(env):
    phone = env.phone()
    body = scan_body(env, phone)
    assert scan(env, body)["decision"] == "ALLOW"
    again = scan(env, body)
    assert again["decision"] == "BLOCK" and again["reasons"] == [R.CHALLENGE_UNKNOWN]


def test_signature_by_another_key_is_refused_before_attestation_work(env):
    phone = env.phone()
    out = scan(env, scan_body(env, phone, signer=ec.generate_private_key(ec.SECP256R1())))
    assert out["decision"] == "BLOCK" and out["reasons"] == [R.SIGNATURE_INVALID]
    assert out["evidence"]["deviceKeySignature"] == "FAILED"
    assert out["evidence"]["freshAttestation"] == "NOT_PROVIDED"   # unauthenticated: not even parsed
    assert "history" not in out
    assert len(env.registry.assurance_history(phone.device_id)) == 1


def test_altered_payload_breaks_signature(env):
    phone = env.phone()
    body = scan_body(env, phone)
    doc = json.loads(base64.b64decode(body["scanData"]))
    doc["signals"] = {"v": 1, "env_in_call": True}
    body["scanData"] = _b64(json.dumps(doc).encode())
    assert R.SIGNATURE_INVALID in scan(env, body)["reasons"]


@pytest.mark.parametrize("edit", [
    lambda d: {**d, "extra": 1},
    lambda d: {k: v for k, v in d.items() if k != "signals"},
    lambda d: {**d, "v": 0},
    lambda d: {**d, "v": True},
    lambda d: {**d, "purpose": "enrollment"},
    lambda d: {**d, "ts": "1"},
    lambda d: {**d, "freshChainSha256": ["AB" * 32]},
    lambda d: {**d, "device": {"model": 7}},
    lambda d: {**d, "signals": [1]},
])
def test_malformed_or_downgraded_transcripts(env, edit):
    phone = env.phone()
    ch = device_challenge(env, phone.device_id).json()
    nonce = b64url_decode(ch["nonce"])
    doc = json.loads(scan_evidence.scan_data(phone.device_id, ch["challengeId"], nonce, int(time.time() * 1000),
                                             None, DEVICE_IDS, None))
    data = json.dumps(edit(doc)).encode()
    out = scan(env, scan_body(env, phone, fresh=False, challenge=ch, data=data))
    assert out["decision"] == "BLOCK" and out["reasons"] == [R.SCAN_EVIDENCE_MALFORMED]


def test_duplicate_keys_are_rejected(env):
    phone = env.phone()
    ch = device_challenge(env, phone.device_id).json()
    raw = scan_evidence.scan_data(phone.device_id, ch["challengeId"], b64url_decode(ch["nonce"]),
                                  int(time.time() * 1000), None, DEVICE_IDS, None)
    data = raw[:-1] + b',"signals":{"v":1}}'
    assert scan(env, scan_body(env, phone, fresh=False, challenge=ch, data=data))["reasons"] == \
           [R.SCAN_EVIDENCE_MALFORMED]


@pytest.mark.parametrize("field", ["deviceId", "challengeId", "nonce"])
def test_transcript_must_describe_this_request(env, field):
    phone = env.phone()
    ch = device_challenge(env, phone.device_id).json()
    doc = json.loads(scan_evidence.scan_data(phone.device_id, ch["challengeId"], b64url_decode(ch["nonce"]),
                                             int(time.time() * 1000), None, DEVICE_IDS, None))
    doc[field] = "other"
    out = scan(env, scan_body(env, phone, fresh=False, challenge=ch, data=json.dumps(doc).encode()))
    assert R.SCAN_EVIDENCE_MISMATCH in out["reasons"]


def test_swapped_or_stripped_chain_mismatches_signed_digests(env):
    phone = env.phone()
    # Chain stripped while the signed digests remain.
    body = scan_body(env, phone)
    del body["freshAttestationChain"]
    assert R.SCAN_EVIDENCE_MISMATCH in scan(env, body)["reasons"]
    # A different (validly attested) chain swapped in after signing.
    ch = device_challenge(env, phone.device_id).json()
    leaf, _ = make_leaf(env.pki, KD(challenge=b64url_decode(ch["nonce"])))
    signed_chain = chain_der(leaf, env.pki.inter, env.pki.root)
    other, _ = make_leaf(env.pki, KD(challenge=b64url_decode(ch["nonce"])))
    body = scan_body(env, phone, challenge=ch, chain=chain_der(other, env.pki.inter, env.pki.root),
                     digests_chain=signed_chain)
    assert scan(env, body)["reasons"] == [R.SCAN_EVIDENCE_MISMATCH]


@pytest.mark.parametrize("offset_ms", [-10 * 60 * 1000, 10 * 60 * 1000])
def test_stale_or_future_transcript(env, offset_ms):
    phone = env.phone()
    out = scan(env, scan_body(env, phone, ts=int(time.time() * 1000) + offset_ms))
    assert R.SCAN_STALE in out["reasons"]


def test_expired_challenge(env):
    phone = env.phone()
    ch = device_challenge(env, phone.device_id).json()
    store = env.service._challenges
    real = store._clock
    store._clock = lambda: real() + env.policy.scan_challenge_ttl_seconds + 1
    assert scan(env, scan_body(env, phone, challenge=ch))["reasons"] == [R.CHALLENGE_UNKNOWN]


def test_challenges_are_not_interchangeable_across_purposes(env):
    phone = env.phone()
    # Action challenge used for a scan, and an enrollment challenge.
    action_ch = env.action_challenge(phone.device_id).json()
    assert scan(env, scan_body(env, phone, challenge=action_ch))["reasons"] == [R.CHALLENGE_UNKNOWN]
    enroll_ch = env.client.post("/v1/challenges").json()
    assert scan(env, scan_body(env, phone, challenge=enroll_ch))["reasons"] == [R.CHALLENGE_UNKNOWN]
    # Key-rotation challenge used for a scan.
    rot_ch = device_challenge(env, phone.device_id, "key-rotation").json()
    assert scan(env, scan_body(env, phone, challenge=rot_ch))["reasons"] == [R.CHALLENGE_UNKNOWN]
    # Scan challenge used for an action, and for a rotation.
    scan_ch = device_challenge(env, phone.device_id).json()
    assert env.verify(env.sign(phone, challenge=scan_ch))["reasons"] == [R.CHALLENGE_UNKNOWN]
    scan_ch = device_challenge(env, phone.device_id).json()
    body, _, _ = rotation_body(env, phone, challenge=scan_ch)
    assert rotate(env, body)["reasons"] == [R.CHALLENGE_UNKNOWN]
    # A challenge for one device cannot scan another.
    other = env.phone()
    ch_other = device_challenge(env, other.device_id).json()
    assert scan(env, scan_body(env, phone, challenge=ch_other))["reasons"] == [R.CHALLENGE_UNKNOWN]


def test_unknown_purpose_is_rejected(env):
    phone = env.phone()
    assert device_challenge(env, phone.device_id, "action").status_code == 422


# --- fresh attestation and downgrades -------------------------------------------

def test_missing_fresh_attestation_blocks_by_default(env):
    phone = env.phone()
    out = scan(env, scan_body(env, phone, fresh=False))
    assert out["decision"] == "BLOCK" and R.SCAN_FRESH_ATTESTATION_MISSING in out["reasons"]
    assert out["evidence"]["freshAttestation"] == "NOT_PROVIDED"
    assert out["history"]["compared"] is False and out["history"]["changes"] == []


def test_operator_may_allow_signature_only_scans_labelled_partial(policy):
    env = Env(policy, scan_require_fresh_attestation=False)
    phone = env.phone()
    out = scan(env, scan_body(env, phone, fresh=False))
    assert out["decision"] == "ALLOW"
    assert out["evidence"]["freshAttestation"] == "NOT_PROVIDED"
    assert len(env.registry.assurance_history(phone.device_id)) == 1  # nothing fresh to record


def test_resending_an_enrolled_key_is_never_fresh(env):
    phone = env.phone()
    # Even a chain carrying the current nonce is refused when its key is the enrolled one.
    out = scan(env, scan_body(env, phone, leaf_key=phone.device_key))
    assert out["decision"] == "BLOCK" and R.FRESH_ATTESTATION_KEY_REUSED in out["reasons"]
    assert out["evidence"]["freshAttestation"] == "FAILED"
    # Another enrolled device's key is refused too.
    other = env.phone()
    out = scan(env, scan_body(env, phone, leaf_key=other.device_key))
    assert R.FRESH_ATTESTATION_KEY_REUSED in out["reasons"]


def test_old_nonce_chain_is_not_fresh(env):
    phone = env.phone()
    out = scan(env, scan_body(env, phone, kd=KD(challenge=b"\x00" * 32)))
    assert out["decision"] == "BLOCK" and out["evidence"]["freshAttestation"] == "FAILED"
    assert len(env.registry.assurance_history(phone.device_id)) == 1


def test_unlocked_bootloader_in_fresh_evidence_blocks_without_snapshot(env):
    phone = env.phone()
    ch = device_challenge(env, phone.device_id).json()
    out = scan(env, scan_body(env, phone, challenge=ch,
                              kd=KD(challenge=b64url_decode(ch["nonce"]), device_locked=False)))
    assert out["decision"] == "BLOCK" and R.BOOTLOADER_UNLOCKED in out["reasons"]
    assert len(env.registry.assurance_history(phone.device_id)) == 1


def test_patch_regression_is_reported_for_review(env):
    phone = env.phone()
    ch = device_challenge(env, phone.device_id).json()
    out = scan(env, scan_body(env, phone, challenge=ch,
                              kd=KD(challenge=b64url_decode(ch["nonce"]), os_patch_level=202601)))
    assert out["decision"] == "ALLOW"   # a diagnostic, not a new block factor
    assert {"code": "PATCH_REGRESSION", "level": "REVIEW", "field": "os_patch_level"} in out["history"]["changes"]


def test_reported_model_mismatch_with_fresh_attestation(env):
    phone = env.phone()
    out = scan(env, scan_body(env, phone, device={**DEVICE_IDS, "model": "Pixel 9"}))
    assert R.DEVICE_ID_MISMATCH in out["reasons"]


def test_scans_do_not_inflate_keybox_history(env):
    phone = env.phone()
    key_sha = env.registry.get(phone.device_id).evidence["attestation_key_sha256"]
    before = env.registry.attestation_key_stats(key_sha, 3600)["enrollments"]
    for _ in range(3):
        assert scan(env, scan_body(env, phone))["decision"] == "ALLOW"
    assert env.registry.attestation_key_stats(key_sha, 3600)["enrollments"] == before


# --- device state and ownership -----------------------------------------------------

def test_pending_revoked_and_quarantined_devices_cannot_scan(policy):
    env = Env(policy)
    _, pending = env.enroll(signals=STEP_UP_SIGNALS)
    revoked = env.phone()
    env.service.revoke_device(revoked.device_id, "test")
    legacy = env.phone()
    quarantine = Env(policy, require_bound_device=True)
    quarantine.registry, quarantine.service._registry = env.registry, env.registry
    quarantine.pki = env.pki
    cases = [(env, pending, R.DEVICE_PENDING), (env, revoked, R.DEVICE_REVOKED),
             (quarantine, legacy, R.DEVICE_REBINDING_REQUIRED)]
    for e, phone, reason in cases:
        for purpose in ("scan", "key-rotation"):
            assert device_challenge(e, phone.device_id, purpose).status_code == 404
        binding = scan_evidence.challenge_binding("scan", phone.device_id)
        c = e.service._challenges.issue(bound_to=binding)
        challenge = {"challengeId": c.challenge_id, "nonce": b64url(c.nonce)}
        assert scan(e, scan_body(e, phone, challenge=challenge))["reasons"] == [reason]
        c = e.service._challenges.issue(bound_to=scan_evidence.challenge_binding("key-rotation", phone.device_id))
        body, _, _ = rotation_body(e, phone, challenge={"challengeId": c.challenge_id, "nonce": b64url(c.nonce)})
        assert rotate(e, body)["reasons"] == [reason]


def test_scans_are_owner_scoped(policy):
    env = gateway_env(policy)
    phone = env.phone()
    assert device_challenge(env, phone.device_id).status_code == 201
    act_as(env, account="bob")
    assert device_challenge(env, phone.device_id).status_code == 404
    act_as(env, account="alice")
    body = scan_body(env, phone)
    for account, tenant in (("bob", "bank"), ("alice", "other-bank")):
        act_as(env, tenant=tenant, account=account)
        out = scan(env, body)
        assert out["reasons"] == [R.DEVICE_UNKNOWN] and "history" not in out
    act_as(env, account="alice")
    assert scan(env, body)["reasons"] == [R.CHALLENGE_UNKNOWN]   # burnt by the stranger's attempt


def test_require_principal_refuses_anonymous_scans(policy):
    env = Env(policy)
    phone = env.phone()
    body = scan_body(env, phone)
    env.service.policy = dataclasses.replace(env.policy, require_principal=True)
    assert scan(env, body)["reasons"] == [R.PRINCIPAL_REQUIRED]
    assert device_challenge(env, phone.device_id).status_code == 404


def test_owner_history_view(policy):
    env = gateway_env(policy)
    phone = env.phone()
    scan(env, scan_body(env, phone))
    history = env.client.get(f"/v1/devices/{phone.device_id}/history").json()
    assert history["deviceId"] == phone.device_id
    newest, oldest = history["snapshots"]
    assert newest["source"] == "scan_refresh" and oldest["source"] == "enrollment"
    assert newest["changes"][0]["code"] == "FRESH_KEY_AUTHORIZED" and oldest["changes"] == []
    flat = json.dumps(history)
    import re
    assert not re.search(r"[0-9a-f]{64}", flat)          # no key or boot-key digests
    for field in ("device_key_sha256", "verified_boot_key_sha256", "attested_ids", "reasons", "risk"):
        assert f'"{field}"' not in flat
    assert AsPrincipal(env.app_client, account="bob").get(f"/v1/devices/{phone.device_id}/history").status_code == 404
    admin = env.app_client.get(f"/v1/admin/devices/{phone.device_id}",
                               headers={"Authorization": "Bearer " + "a" * 40}).json()
    assert [h["source"] for h in admin["history"]] == ["scan_refresh", "enrollment"]
    assert admin["decisions"][0]["kind"] == "scan"


# --- Play Integrity -------------------------------------------------------------

def test_play_verdict_bound_to_the_scan_transcript(policy):
    env = Env(policy, decoder=EchoDecoder())
    phone = env.phone()
    out = scan(env, scan_body(env, phone, play=True))
    assert out["decision"] == "ALLOW" and out["evidence"]["playIntegrity"] == "VERIFIED"
    # A token minted for another request hash (e.g. an enrollment or action) does not fit.
    body = scan_body(env, phone)
    body["playIntegrityToken"] = scan_evidence.request_hash("key-rotation", base64.b64decode(body["scanData"]))
    out = scan(env, body)
    assert R.PLAY_INTEGRITY_REQUEST_MISMATCH in out["reasons"] and out["evidence"]["playIntegrity"] == "FAILED"


def test_play_failing_device_verdict(policy):
    env = Env(policy, decoder=EchoDecoder(verdicts=()))
    phone = env.phone()
    out = scan(env, scan_body(env, phone, play=True))
    assert R.PLAY_DEVICE_INTEGRITY_FAILED in out["reasons"] and out["evidence"]["playIntegrity"] == "FAILED"


class BrokenDecoder:
    def decode(self, package_name, token):
        raise DecodeError("google unreachable")


@pytest.mark.parametrize("decoder", [None, BrokenDecoder()])
def test_unavailable_play_is_explicit(policy, decoder):
    env = Env(policy, decoder=decoder)
    phone = env.phone()
    out = scan(env, scan_body(env, phone, play=True))
    assert out["decision"] == "ALLOW" and out["evidence"]["playIntegrity"] == "UNAVAILABLE"
    assert R.PLAY_INTEGRITY_UNAVAILABLE in out["warnings"]
    required = Env(policy, decoder=decoder, scan_require_play_integrity=True)
    phone = required.phone()
    out = scan(required, scan_body(required, phone, play=True))
    assert out["decision"] == "BLOCK" and R.PLAY_INTEGRITY_UNAVAILABLE in out["reasons"]
    out = scan(required, scan_body(required, phone))
    assert R.PLAY_INTEGRITY_MISSING in out["reasons"] and out["evidence"]["playIntegrity"] == "NOT_PROVIDED"


# --- concurrency --------------------------------------------------------------------

def test_concurrent_submissions_of_one_challenge_accept_exactly_one(env):
    phone = env.phone()
    body = scan_body(env, phone)
    request = ScanRequest(body["deviceId"], body["challengeId"], base64.b64decode(body["scanData"]),
                          base64.b64decode(body["signature"]),
                          [base64.b64decode(c) for c in body["freshAttestationChain"]])
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda _: env.service.verify_scan(request), range(8)))
    assert sum(r.decision == "ALLOW" for r in results) == 1
    assert all(r.reasons == (R.CHALLENGE_UNKNOWN,) for r in results if r.decision != "ALLOW")
    assert len(env.registry.assurance_history(phone.device_id)) == 2


def test_concurrent_scans_of_one_device_each_record_history(env):
    phone = env.phone()
    bodies = [scan_body(env, phone) for _ in range(6)]
    with ThreadPoolExecutor(6) as pool:
        outs = list(pool.map(lambda b: scan(env, b), bodies))
    assert all(o["decision"] == "ALLOW" for o in outs)
    assert len(env.registry.assurance_history(phone.device_id)) == 7


# --- key rotation -------------------------------------------------------------------

def test_rotation_keeps_device_and_switches_keys(env):
    phone = env.phone(confirm=BIOMETRIC)
    body, new_key, new_confirm = rotation_body(env, phone, confirm=True)
    out = rotate(env, body)
    assert out == {**out, "decision": "ALLOW", "rotated": True, "hasConfirmKey": True}, out
    record = env.registry.get(phone.device_id)
    assert record.status == "active" and record.binding == "LEGACY_UNBOUND"
    # The old key no longer signs for this device; the new one does.
    assert env.verify(env.sign(phone))["reasons"] == [R.SIGNATURE_INVALID]
    rotated = dataclasses.replace(phone, device_key=new_key, confirm_key=new_confirm)
    assert env.verify(env.sign(rotated))["decision"] == "ALLOW"
    assert env.verify(env.sign(rotated, key="confirm"))["decision"] == "ALLOW"
    events = env.registry.lifecycle_events(phone.device_id)
    assert events[0]["event"] == "key_rotated" and events[0]["from"] == events[0]["to"] == "active"
    # History links the rotation to the enrolled key, then scans continue from the new key.
    out = scan(env, scan_body(env, rotated))
    assert out["history"]["previousSource"] == "key_rotation"
    assert out["history"]["changes"][0]["code"] == "FRESH_KEY_AUTHORIZED"
    history = env.client.get(f"/v1/admin/devices/{phone.device_id}",
                             headers={"Authorization": "Bearer " + "a" * 40}).json()["history"]
    assert [h["source"] for h in history] == ["scan_refresh", "key_rotation", "enrollment"]
    assert history[1]["changes"][0]["code"] == "KEY_ROTATED"
    assert not any(c["code"] == "KEY_CONTINUITY_UNVERIFIED" for h in history for c in h["changes"])


def test_rotation_without_confirm_chain_removes_the_confirm_key(env):
    phone = env.phone(confirm=BIOMETRIC)
    body, new_key, _ = rotation_body(env, phone)
    assert rotate(env, body)["hasConfirmKey"] is False
    assert env.registry.get(phone.device_id).confirm_key_spki is None


def test_retired_key_never_enrolls_or_rotates_again(env):
    phone = env.phone()
    body, new_key, _ = rotation_body(env, phone)
    assert rotate(env, body)["rotated"]
    # Re-enrolling the retired key is refused.
    ch = env.client.post("/v1/challenges").json()
    leaf, _ = make_leaf(env.pki, KD(challenge=b64url_decode(ch["nonce"])), leaf_key=phone.device_key)
    out = env.client.post("/v1/enrollments", json={
        "challengeId": ch["challengeId"], "device": DEVICE_IDS,
        "attestationChain": [_b64(c) for c in chain_der(leaf, env.pki.inter, env.pki.root)]}).json()
    assert out["decision"] == "BLOCK" and out["reasons"] == [R.KEY_ALREADY_ENROLLED]
    # Rotating back to the retired key is refused.
    rotated = dataclasses.replace(phone, device_key=new_key)
    body, _, _ = rotation_body(env, rotated, new_key=phone.device_key)
    out = rotate(env, body)
    assert not out["rotated"] and R.KEY_ALREADY_ENROLLED in out["reasons"]


def test_rotation_requires_both_signatures(env):
    phone = env.phone()
    stranger = ec.generate_private_key(ec.SECP256R1())
    body, _, _ = rotation_body(env, phone, old_signer=stranger)
    out = rotate(env, body)
    assert not out["rotated"] and out["reasons"] == [R.SIGNATURE_INVALID]
    body, _, _ = rotation_body(env, phone, new_signer=stranger)
    out = rotate(env, body)
    assert not out["rotated"] and R.KEY_ROTATION_PROOF_INVALID in out["reasons"]
    assert env.verify(env.sign(phone))["decision"] == "ALLOW"   # nothing changed


def test_rotation_to_an_enrolled_key_is_refused(env):
    phone, other = env.phone(), env.phone()
    body, _, _ = rotation_body(env, phone, new_key=other.device_key)
    out = rotate(env, body)
    assert not out["rotated"] and R.KEY_ALREADY_ENROLLED in out["reasons"]


def test_rotation_with_failing_or_risky_evidence_changes_nothing(env):
    phone = env.phone()
    ch = device_challenge(env, phone.device_id, "key-rotation").json()
    body, _, _ = rotation_body(env, phone, challenge=ch,
                               kd=KD(challenge=b64url_decode(ch["nonce"]), device_locked=False))
    out = rotate(env, body)
    assert out["decision"] == "BLOCK" and not out["rotated"] and R.BOOTLOADER_UNLOCKED in out["reasons"]
    assert env.verify(env.sign(phone))["decision"] == "ALLOW"
    assert [e["event"] for e in env.registry.lifecycle_events(phone.device_id)] == ["enrolled"]


def test_rotation_step_up_changes_nothing(policy):
    env = Env(policy)
    phone = env.phone()
    # Make every rotation score STEP_UP (enrollment thresholds apply to the new key).
    risk = env.policy.risk
    env.service.policy = dataclasses.replace(env.policy, risk=dataclasses.replace(
        risk, enrollment_thresholds=dataclasses.replace(risk.enrollment_thresholds, allow_below=0)))
    before = env.registry.get(phone.device_id).public_key_spki
    out = rotate(env, rotation_body(env, phone)[0])
    assert out["decision"] == "STEP_UP" and not out["rotated"] and "hasConfirmKey" not in out
    assert env.registry.get(phone.device_id).public_key_spki == before


def test_rotation_replay_and_owner_scope(policy):
    env = gateway_env(policy)
    phone = env.phone()
    body, _, _ = rotation_body(env, phone)
    act_as(env, account="bob")
    assert rotate(env, body)["reasons"] == [R.DEVICE_UNKNOWN]
    act_as(env, account="alice")
    assert rotate(env, body)["reasons"] == [R.CHALLENGE_UNKNOWN]
    body, _, _ = rotation_body(env, phone)
    assert rotate(env, body)["rotated"]
    assert rotate(env, body)["reasons"] == [R.CHALLENGE_UNKNOWN]


def test_concurrent_rotations_from_one_key_rotate_exactly_once(policy):
    # Each verified rotation attempt counts in keybox history, like an enrollment; every test
    # chain shares one synthetic keybox, so lift the reuse threshold for this test only.
    env = Env(policy)
    env.service.policy = dataclasses.replace(env.policy, risk=dataclasses.replace(
        env.policy.risk, keybox_reuse_threshold=100))
    phone = env.phone()
    bodies = [rotation_body(env, phone)[0] for _ in range(4)]
    with ThreadPoolExecutor(4) as pool:
        outs = list(pool.map(lambda b: rotate(env, b), bodies))
    assert sum(o["rotated"] for o in outs) == 1
    for o in outs:
        if not o["rotated"]:
            assert set(o["reasons"]) & {R.KEY_ROTATION_CONFLICT, R.SIGNATURE_INVALID}
    assert [e["event"] for e in env.registry.lifecycle_events(phone.device_id)].count("key_rotated") == 1


def test_registry_rotation_is_compare_and_swap(env):
    import hashlib
    phone = env.phone()
    record = env.registry.get(phone.device_id)
    old = hashlib.sha256(record.public_key_spki).hexdigest()
    verifier = env.service._verifier
    outcomes = []
    for _ in range(2):
        nonce = b"n" * 32
        leaf, key = make_leaf(env.pki, KD(challenge=nonce))
        att = verifier.verify(chain_der(leaf, env.pki.inter, env.pki.root), nonce, DEVICE_IDS)
        outcomes.append(env.registry.rotate_key(phone.device_id, old, att.leaf_public_key_spki, att.evidence,
                                                None, None))
    assert outcomes == [True, False]


# --- history compatibility, retention, migration ------------------------------------

def _snap(**kw):
    base = {"v": 1, "leaf_spki_sha256": "aa" * 32, "device_locked": True, "verified_boot_state": "VERIFIED",
            "verified_boot_key_sha256": "cd" * 32, "os_patch_level": 202609, "vendor_patch_level": 20260905,
            "boot_patch_level": 20260905, "attested_ids": {"model": "m"}}
    base.update(kw)
    return base


def test_legacy_snapshots_compare_with_new_ones():
    legacy = _snap()                                   # pre-Run-17: no source / device key
    refresh = _snap(leaf_spki_sha256="ee" * 32, source="scan_refresh", device_key_sha256="aa" * 32)
    assert compare_continuity(legacy, refresh)[0]["code"] == "FRESH_KEY_AUTHORIZED"
    stranger = _snap(leaf_spki_sha256="ee" * 32, source="scan_refresh", device_key_sha256="bb" * 32)
    assert compare_continuity(legacy, stranger) == [
        {"code": "KEY_CONTINUITY_UNVERIFIED", "level": "REVIEW", "field": "device_key_sha256"}]
    rotation = _snap(leaf_spki_sha256="bb" * 32, source="key_rotation", device_key_sha256="bb" * 32,
                     authorized_by_sha256="aa" * 32)
    assert compare_continuity(legacy, rotation)[0]["code"] == "KEY_ROTATED"
    forged = dict(rotation, authorized_by_sha256="cc" * 32)
    assert compare_continuity(legacy, forged)[0]["code"] == "KEY_CONTINUITY_UNVERIFIED"
    # Same-leaf comparisons are unchanged from Run 22.
    assert compare_continuity(legacy, _snap()) == []
    with pytest.raises(ValueError):
        compare_continuity({"v": 2}, refresh)


def test_refresh_snapshots_are_bounded(policy):
    env = Env(policy, history_max_snapshots=2)
    phone = env.phone()
    for _ in range(3):
        scan(env, scan_body(env, phone))
    sources = [h["evidence"]["source"] for h in env.registry.assurance_history(phone.device_id, 100)]
    assert sources == ["scan_refresh", "scan_refresh", "enrollment"]


def test_rotation_snapshots_are_never_pruned(policy):
    env = Env(policy, history_max_snapshots=1)
    phone = env.phone()
    body, key, _ = rotation_body(env, phone)
    assert rotate(env, body)["rotated"]
    phone = dataclasses.replace(phone, device_key=key)
    for _ in range(3):
        scan(env, scan_body(env, phone))
    sources = [h["evidence"]["source"] for h in env.registry.assurance_history(phone.device_id, 100)]
    assert sources == ["scan_refresh", "key_rotation", "enrollment"]


def test_run16_database_upgrades_with_snapshots(tmp_path, monkeypatch):
    path = tmp_path / "r16.sqlite"
    monkeypatch.setattr(registry_module, "MIGRATIONS", registry_module.MIGRATIONS[:2])
    monkeypatch.setattr(registry_module, "SCHEMA_VERSION", 2)
    old = DeviceRegistry(path)
    assert old.schema_version() == 2
    old._conn.execute("INSERT INTO devices (device_id, public_key_spki, spki_sha256, enrolled_at, evidence_json)"
                      " VALUES ('dev_16', x'01', 'k16', 1, '{}')")
    old._conn.execute("INSERT INTO assurance_snapshots VALUES ('dev_16', ?, 2.0)", (json.dumps(_snap()),))
    old._conn.commit()
    old._conn.close()
    monkeypatch.undo()
    reg = DeviceRegistry(path)
    assert reg.schema_version() == registry_module.SCHEMA_VERSION == 3
    assert reg.assurance_history("dev_16")[0]["evidence"] == _snap()
    reg.record_snapshot("dev_16", _snap(source="scan_refresh", device_key_sha256="aa" * 32), keep=1)
    reg.record_snapshot("dev_16", _snap(source="scan_refresh", device_key_sha256="aa" * 32), keep=1)
    assert len(reg.assurance_history("dev_16")) == 2  # legacy enrollment row kept, one refresh
    assert not reg.key_known("never")
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 4")
    conn.commit()
    conn.close()
    with pytest.raises(SchemaVersionError):
        DeviceRegistry(path)


def test_enrollment_and_rotation_snapshots_cannot_be_injected(env):
    phone = env.phone()
    with pytest.raises(ValueError):
        env.registry.record_snapshot(phone.device_id, _snap(source="enrollment"), keep=5)
    with pytest.raises(ValueError):
        env.registry.record_snapshot(phone.device_id, _snap(source="key_rotation"), keep=5)


# --- policy traceability ------------------------------------------------------------

def test_policy_digest_tracks_policy_but_not_secrets(policy):
    base = policy.digest()
    assert len(base) == 16 and base == dataclasses.replace(policy).digest()
    assert dataclasses.replace(policy, fleet_hash_key="secret").digest() == base
    assert dataclasses.replace(policy, max_os_patch_age_months=6).digest() != base
    assert dataclasses.replace(policy, policy_version="x").digest() != base


@pytest.mark.parametrize("key,value", [
    ("policy_version", "has space"), ("policy_version", "x" * 65), ("scan_max_age_seconds", 0),
    ("history_max_snapshots", -1), ("scan_require_fresh_attestation", "yes"),
])
def test_policy_validation(policy, key, value):
    from device_trust.policy import TrustPolicy
    raw = {"package_name": policy.package_name, "signing_cert_sha256": sorted(policy.signing_cert_sha256), key: value}
    with pytest.raises(ValueError):
        TrustPolicy.from_dict(raw)


def test_transcript_hash_domains_are_distinct():
    data = b'{"v":1}'
    from device_trust.actions import action_request_hash
    from device_trust.enrollment_proof import proof_request_hash
    hashes_ = {scan_evidence.request_hash("scan", data), scan_evidence.request_hash("key-rotation", data),
               action_request_hash(data), proof_request_hash(data)}
    assert len(hashes_) == 4
