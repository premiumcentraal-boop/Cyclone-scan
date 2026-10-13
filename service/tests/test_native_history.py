"""Unauthenticated attempts must not poison trusted key/device history."""
import base64
from attestation_factory import KD, DEVICE_IDS, make_leaf, chain_der
from test_actions import Env
from device_trust import reasons as R

def test_wrong_challenge_cannot_poison_keybox_history(policy):
    env = Env(policy)
    phone = env.phone()
    key_sha = env.registry.get(phone.device_id).evidence["attestation_key_sha256"]
    before = env.registry.attestation_key_stats(key_sha, 3600)
    for _ in range(6):
        ch = env.client.post("/v1/challenges").json()
        leaf, _ = make_leaf(env.pki, KD(challenge=b"wrong nonce"))
        body = {"challengeId": ch["challengeId"], "device": DEVICE_IDS,
                "attestationChain": [base64.b64encode(cert).decode()
                                    for cert in chain_der(leaf, env.pki.inter, env.pki.root)]}
        out = env.client.post("/v1/enrollments", json=body).json()
        assert R.CHALLENGE_MISMATCH in out["reasons"]
    assert env.registry.attestation_key_stats(key_sha, 3600) == before

def test_bad_signatures_do_not_count_as_fleet_devices(policy):
    env = Env(policy)
    phone = env.phone()
    body = env.sign(phone)
    body["signature"] = base64.b64encode(b"bad").decode()
    out = env.verify(body)
    assert R.SIGNATURE_INVALID in out["reasons"]
    rows = env.registry._conn.execute(
        "SELECT kind, device_id FROM fleet_events WHERE kind LIKE 'action%'").fetchall()
    assert rows == [("action_attempt", None)]
