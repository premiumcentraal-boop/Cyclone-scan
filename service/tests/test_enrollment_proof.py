"""Run 20: evidence binding, downgrade rejection and strict signed payloads."""
import base64
import dataclasses
import json
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from attestation_factory import DEVICE_IDS, KD, make_leaf, chain_der
from test_actions import Env
from device_trust import reasons as R
from device_trust.actions import SignedDataError, parse_signed_data
from device_trust.enrollment_proof import proof_data, proof_request_hash
from device_trust.play_integrity import b64url_decode

def bound_body(env, signals=None, confirm=False):
    ch = env.client.post("/v1/challenges").json()
    nonce = b64url_decode(ch["nonce"])
    leaf, key = make_leaf(env.pki, KD(challenge=nonce))
    chain = chain_der(leaf, env.pki.inter, env.pki.root)
    cc = None
    if confirm:
        cleaf, _ = make_leaf(env.pki, KD(challenge=nonce, no_auth_required=False, user_auth_type=2))
        cc = chain_der(cleaf, env.pki.inter, env.pki.root)
    data = proof_data(ch["challengeId"], nonce, chain, cc, DEVICE_IDS, signals)
    body = {"challengeId": ch["challengeId"], "device": dict(DEVICE_IDS),
            "attestationChain": [base64.b64encode(c).decode() for c in chain],
            "evidenceData": base64.b64encode(data).decode(),
            "evidenceSignature": base64.b64encode(key.sign(data, ec.ECDSA(hashes.SHA256()))).decode()}
    if cc:
        body["confirmKeyChain"] = [base64.b64encode(c).decode() for c in cc]
    if signals is not None:
        body["signals"] = signals
    return body, key, data

def test_bound_enrollment_succeeds_and_is_single_use(policy):
    env = Env(policy, require_bound_enrollment=True)
    body, _, _ = bound_body(env, {"v": 1})
    assert env.client.post("/v1/enrollments", json=body).json()["decision"] == "ALLOW"
    out = env.client.post("/v1/enrollments", json=body).json()
    assert R.CHALLENGE_UNKNOWN in out["reasons"]

@pytest.mark.parametrize("edit", ["signals", "device", "confirm", "signature", "proof", "strip", "one_field"])
def test_submission_edits_or_downgrades_block(policy, edit):
    env = Env(policy, require_bound_enrollment=True)
    body, _, _ = bound_body(env, {"v": 1, "root_su": False}, confirm=True)
    if edit == "signals": body["signals"]["root_su"] = True
    elif edit == "device": body["device"]["model"] = "other"
    elif edit == "confirm": del body["confirmKeyChain"]
    elif edit == "signature": body["evidenceSignature"] = base64.b64encode(b"wrong").decode()
    elif edit == "proof": body["evidenceData"] = base64.b64encode(b'{"v":1}').decode()
    elif edit == "strip":
        del body["evidenceData"]; del body["evidenceSignature"]
    else: del body["evidenceSignature"]
    out = env.client.post("/v1/enrollments", json=body).json()
    assert out["decision"] == "BLOCK"
    assert set(out["reasons"]) & {R.ENROLLMENT_PROOF_INVALID, R.ENROLLMENT_PROOF_MISSING}

def test_invalid_proof_does_not_poison_key_history(policy):
    env = Env(policy, require_bound_enrollment=True)
    body, _, _ = bound_body(env)
    body["evidenceSignature"] = base64.b64encode(b"wrong").decode()
    env.client.post("/v1/enrollments", json=body)
    assert env.registry._conn.execute("SELECT COUNT(*) FROM attestation_key_uses").fetchone()[0] == 0

def test_missing_proof_is_explicit_in_legacy_mode(policy):
    data, _ = Env(policy).enroll()
    assert data["decision"] == "ALLOW"
    assert R.ENROLLMENT_LEGACY_UNBOUND in data["warnings"]

def test_play_hash_uses_exact_proof_bytes(policy):
    from test_actions import EchoDecoder
    env = Env(policy, decoder=EchoDecoder(), require_bound_enrollment=True, require_play_integrity=True)
    body, _, data = bound_body(env)
    body["playIntegrityToken"] = proof_request_hash(data)
    assert env.client.post("/v1/enrollments", json=body).json()["decision"] == "ALLOW"

@pytest.mark.parametrize("data", [
    b'{"v":1,"v":1}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}',
    b'{"a":{"x":1,"x":2}}', b'{"a":"\\ud800"}', b"[" * 100 + b"0" + b"]" * 100,
])
def test_strict_signed_json_rejects_ambiguous_or_excessive_inputs(data):
    with pytest.raises(SignedDataError):
        parse_signed_data(data)

def test_proof_policy_rejects_string_boolean(policy):
    from device_trust.policy import TrustPolicy
    with pytest.raises(ValueError):
        TrustPolicy.from_dict({"package_name": "p", "signing_cert_sha256": ["ab"*32],
                               "require_bound_enrollment": "false"})
