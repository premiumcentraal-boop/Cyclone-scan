"""Phase 2: device binding, biometric confirm key and signed actions."""

import base64
import dataclasses
import json
import sqlite3
import time

import pytest
from attestation_factory import DEVICE_IDS, KD, chain_der, make_leaf, make_pki
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from device_trust import reasons as R
from device_trust.actions import SignedDataError, action_request_hash, parse_signed_data
from device_trust.api import create_app
from device_trust.attestation import AttestationVerifier
from device_trust.challenges import ChallengeStore
from device_trust.play_integrity import b64url, b64url_decode
from device_trust.registry import DeviceRegistry
from device_trust.revocation import RevocationList
from device_trust.roots import RootStore
from device_trust.service import DeviceTrustService, confirm_key_auth_ok

ADMIN = "a" * 40
BIOMETRIC = {"no_auth_required": False, "user_auth_type": 2}


class EchoDecoder:
    """Fake Play decode API: the 'token' is the requestHash the device sent."""

    def __init__(self, verdicts=("MEETS_DEVICE_INTEGRITY",)):
        self.verdicts = list(verdicts)

    def decode(self, package_name, token):
        from attestation_factory import PACKAGE, SIGNING_DIGEST

        return {
            "requestDetails": {"requestPackageName": package_name, "requestHash": token,
                               "timestampMillis": str(int(time.time() * 1000))},
            "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED", "packageName": PACKAGE,
                             "certificateSha256Digest": [b64url(SIGNING_DIGEST)]},
            "deviceIntegrity": {"deviceRecognitionVerdict": self.verdicts},
        }


@dataclasses.dataclass
class Phone:
    device_id: str
    device_key: ec.EllipticCurvePrivateKey
    confirm_key: ec.EllipticCurvePrivateKey | None


class Env:
    def __init__(self, policy, *, decoder=None, **policy_overrides):
        self.pki = make_pki()
        self.policy = dataclasses.replace(policy, **policy_overrides)
        self.registry = DeviceRegistry()
        self.service = DeviceTrustService(
            self.policy,
            AttestationVerifier(self.policy, RootStore([self.pki.root]), RevocationList.static({})),
            ChallengeStore(self.policy.challenge_ttl_seconds),
            self.registry,
            decoder,
        )
        self.client = TestClient(create_app(self.service, expose_reasons=True, admin_token=ADMIN))

    def enroll(self, *, confirm: dict | None = None, confirm_pki=None, confirm_ids=None, reuse_key=False):
        ch = self.client.post("/v1/challenges").json()
        nonce = b64url_decode(ch["nonce"])
        leaf, key = make_leaf(self.pki, KD(challenge=nonce))
        body = {"challengeId": ch["challengeId"], "device": DEVICE_IDS,
                "attestationChain": [base64.b64encode(c).decode() for c in chain_der(leaf, self.pki.inter, self.pki.root)]}
        confirm_key = None
        if confirm is not None:
            pki = confirm_pki or self.pki
            kd = KD(challenge=nonce, **confirm)
            if confirm_ids is not None:
                kd.attested_ids = confirm_ids
            cleaf, confirm_key = make_leaf(pki, kd, leaf_key=key if reuse_key else None)
            body["confirmKeyChain"] = [base64.b64encode(c).decode() for c in chain_der(cleaf, pki.inter, pki.root)]
        data = self.client.post("/v1/enrollments", json=body).json()
        return data, Phone(data.get("deviceId"), key, confirm_key)

    def phone(self, **kw) -> Phone:
        data, phone = self.enroll(**kw)
        assert data["decision"] == "ALLOW", data
        return phone

    def action_challenge(self, device_id):
        return self.client.post("/v1/action-challenges", json={"deviceId": device_id})

    def sign(self, phone: Phone, action_type="login", params=None, *, key="device", ts=None, overrides=None,
             signer=None, challenge=None, raw=None, play=False):
        ch = challenge or self.action_challenge(phone.device_id).json()
        doc = {"v": 1, "deviceId": phone.device_id, "challengeId": ch["challengeId"], "nonce": ch["nonce"],
               "ts": int(time.time() * 1000) if ts is None else ts,
               "action": {"type": action_type, "params": params or {}}}
        doc.update(overrides or {})
        signed = raw if raw is not None else json.dumps(doc, separators=(",", ":")).encode()
        private = signer or (phone.confirm_key if key == "confirm" else phone.device_key)
        sig = private.sign(signed, ec.ECDSA(hashes.SHA256()))
        body = {"deviceId": phone.device_id, "challengeId": ch["challengeId"],
                "signedData": base64.b64encode(signed).decode(), "signature": base64.b64encode(sig).decode(),
                "key": key}
        if play:
            body["playIntegrityToken"] = action_request_hash(signed)
        return body

    def verify(self, body):
        return self.client.post("/v1/actions/verify", json=body).json()


@pytest.fixture
def env(policy):
    return Env(policy)


# --- happy paths ----------------------------------------------------------

def test_signed_action_allowed_and_returns_exactly_what_was_signed(env):
    phone = env.phone()
    params = {"payee": "NL91ABNA0417164300", "amountCents": 12500, "currency": "EUR"}
    out = env.verify(env.sign(phone, "payment", params))
    assert out["decision"] == "ALLOW", out
    assert out["action"] == {"type": "payment", "params": params}


def test_biometric_confirm_key_enrollment_and_high_risk_action(policy):
    env = Env(policy, confirm_key_required_actions=frozenset({"payment"}))
    phone = env.phone(confirm=BIOMETRIC)
    assert env.registry.get(phone.device_id).confirm_key_spki is not None
    assert env.verify(env.sign(phone, "payment", {"amountCents": 1}, key="confirm"))["decision"] == "ALLOW"


def test_high_risk_action_with_device_key_steps_up(policy):
    env = Env(policy, confirm_key_required_actions=frozenset({"payment"}))
    phone = env.phone(confirm=BIOMETRIC)
    out = env.verify(env.sign(phone, "payment", {"amountCents": 1}))
    assert out["decision"] == "STEP_UP" and out["reasons"] == [R.CONFIRM_KEY_REQUIRED]
    assert "action" not in out


def test_device_without_confirm_key_steps_up_for_high_risk(policy):
    env = Env(policy, confirm_key_required_actions=frozenset({"payment"}))
    phone = env.phone()
    assert env.verify(env.sign(phone, "payment"))["decision"] == "STEP_UP"
    # ... but low-risk actions still work
    assert env.verify(env.sign(phone, "login"))["decision"] == "ALLOW"


# --- binding / replay -----------------------------------------------------

def test_action_challenge_is_single_use(env):
    phone = env.phone()
    body = env.sign(phone)
    assert env.verify(body)["decision"] == "ALLOW"
    replay = env.verify(body)
    assert replay["decision"] == "BLOCK" and replay["reasons"] == [R.CHALLENGE_UNKNOWN]


def test_challenge_bound_to_other_device_rejected(env):
    a, b = env.phone(), env.phone()
    ch_for_a = env.action_challenge(a.device_id).json()
    out = env.verify(env.sign(b, challenge=ch_for_a))
    assert out["reasons"] == [R.CHALLENGE_UNKNOWN]


def test_enrollment_and_action_challenges_are_not_interchangeable(env):
    phone = env.phone()
    enroll_ch = env.client.post("/v1/challenges").json()
    assert env.verify(env.sign(phone, challenge=enroll_ch))["reasons"] == [R.CHALLENGE_UNKNOWN]
    action_ch = env.action_challenge(phone.device_id).json()
    nonce = b64url_decode(action_ch["nonce"])
    leaf, _ = make_leaf(env.pki, KD(challenge=nonce))
    body = {"challengeId": action_ch["challengeId"], "device": DEVICE_IDS,
            "attestationChain": [base64.b64encode(c).decode() for c in chain_der(leaf, env.pki.inter, env.pki.root)]}
    assert env.client.post("/v1/enrollments", json=body).json()["reasons"] == [R.CHALLENGE_UNKNOWN]


def test_tampered_params_break_signature(env):
    phone = env.phone()
    body = env.sign(phone, "payment", {"amountCents": 100})
    signed = json.loads(base64.b64decode(body["signedData"]))
    signed["action"]["params"]["amountCents"] = 100000
    body["signedData"] = base64.b64encode(json.dumps(signed, separators=(",", ":")).encode()).decode()
    assert R.SIGNATURE_INVALID in env.verify(body)["reasons"]


def test_signature_from_another_key_rejected(env):
    phone = env.phone()
    attacker = ec.generate_private_key(ec.SECP256R1())
    assert env.verify(env.sign(phone, signer=attacker))["reasons"] == [R.SIGNATURE_INVALID]


def test_confirm_key_claim_without_confirm_key_rejected(env):
    phone = env.phone()
    out = env.verify(env.sign(phone, key="confirm", signer=phone.device_key))
    assert out["decision"] == "BLOCK" and R.SIGNATURE_INVALID in out["reasons"]


@pytest.mark.parametrize("field", ["deviceId", "challengeId", "nonce"])
def test_signed_fields_must_match_request(env, field):
    phone = env.phone()
    out = env.verify(env.sign(phone, overrides={field: "something-else"}))
    assert R.SIGNED_DATA_MISMATCH in out["reasons"]


@pytest.mark.parametrize("delta_ms", [-10 * 60_000, 10 * 60_000])
def test_stale_or_future_action_rejected(env, delta_ms):
    phone = env.phone()
    out = env.verify(env.sign(phone, ts=int(time.time() * 1000) + delta_ms))
    assert R.ACTION_STALE in out["reasons"]


def test_action_type_allowlist(policy):
    env = Env(policy, allowed_action_types=frozenset({"login"}))
    phone = env.phone()
    assert env.verify(env.sign(phone, "wire_everything"))["reasons"] == [R.ACTION_TYPE_NOT_ALLOWED]


# --- malformed signed data --------------------------------------------------

@pytest.mark.parametrize(
    "raw",
    [
        b'{"v":1,"v":1}',
        b"not json",
        b"\xff\xfe",
        b"[1,2]",
        b'{"v":true,"deviceId":"d","challengeId":"c","nonce":"n","ts":1,"action":{"type":"x","params":{}}}',
        b'{"v":1,"deviceId":"d","challengeId":"c","nonce":"n","ts":1.5,"action":{"type":"x","params":{}}}',
        b'{"v":1,"deviceId":"d","challengeId":"c","nonce":"n","ts":1,"action":{"type":"X Y","params":{}}}',
        b'{"v":1,"deviceId":"d","challengeId":"c","nonce":"n","ts":1,"action":{"type":"x","params":[]}}',
        b'{"v":1,"deviceId":"d","challengeId":"c","nonce":"n","ts":1,"action":{"type":"x","params":{}},"extra":1}',
        b'{"v":1,"deviceId":"d","challengeId":"c","nonce":"n","ts":1,'
        b'"action":{"type":"x","params":{"amount":1,"amount":999}}}',
    ],
)
def test_malformed_signed_data(raw):
    with pytest.raises(SignedDataError):
        parse_signed_data(raw)


def test_malformed_signed_data_blocks_via_api(env):
    phone = env.phone()
    out = env.verify(env.sign(phone, raw=b'{"v":1}'))
    assert out["reasons"] == [R.SIGNED_DATA_MALFORMED]


# --- confirm key attestation ---------------------------------------------------

@pytest.mark.parametrize(
    "confirm",
    [
        {"no_auth_required": True},                                    # plain key posing as confirm key
        {"no_auth_required": False, "user_auth_type": 1},              # PIN/password only
        {"no_auth_required": False, "user_auth_type": 2, "auth_timeout": 300},  # 5-minute unlock window
        {"no_auth_required": False, "user_auth_type": 3},              # biometric OR PIN (not allowed by default)
        {"no_auth_required": False},                                   # auth required but type missing
    ],
)
def test_weak_confirm_keys_rejected(env, confirm):
    data, _ = env.enroll(confirm=confirm)
    assert data["decision"] == "BLOCK"
    assert R.CONFIRM_KEY_NOT_USER_AUTH_BOUND in data["reasons"]


def test_device_credential_allowed_when_policy_says_so(policy):
    env = Env(policy, confirm_key_allow_device_credential=True)
    data, _ = env.enroll(confirm={"no_auth_required": False, "user_auth_type": 3})
    assert data["decision"] == "ALLOW", data


def test_confirm_key_from_another_device_rejected(env):
    data, _ = env.enroll(confirm=BIOMETRIC, confirm_ids=dict(DEVICE_IDS, model="Other"))
    assert R.CONFIRM_KEY_INVALID in data["reasons"]


def test_confirm_key_must_differ_from_device_key(env):
    data, _ = env.enroll(confirm=BIOMETRIC, reuse_key=True)
    assert R.CONFIRM_KEY_INVALID in data["reasons"]


def test_confirm_chain_with_untrusted_root_rejected(env):
    data, _ = env.enroll(confirm=BIOMETRIC, confirm_pki=make_pki(root_cn="Attacker"))
    assert data["reasons"] == [R.CONFIRM_KEY_INVALID]


def test_real_password_only_key_is_not_a_confirm_key():
    """Google test chain: userAuthType=PASSWORD, authTimeout=2^31-1."""
    from test_real_chains import run

    result, exp = run("akita_sdk34_TEE_RSA_NONE_USERAUTH")
    assert result.evidence.user_auth_type == int(exp["hardwareEnforced"]["userAuthType"]) == 1
    assert result.evidence.auth_timeout == 2147483647
    assert not confirm_key_auth_ok(result.evidence)


def test_real_plain_key_reports_no_auth_required():
    from test_real_chains import run

    result, _ = run("caiman_sdk36_TEE_EC_RKP")
    assert result.evidence.no_auth_required is True
    assert not confirm_key_auth_ok(result.evidence)


# --- revocation ----------------------------------------------------------------

def test_revoked_device_cannot_get_challenges_or_act(env):
    phone = env.phone()
    pending = env.sign(phone)
    r = env.client.post(f"/v1/admin/devices/{phone.device_id}/revoke", json={"reason": "lost phone"},
                        headers={"Authorization": f"Bearer {ADMIN}"})
    assert r.status_code == 204
    assert env.action_challenge(phone.device_id).status_code == 404
    assert env.verify(pending)["reasons"] == [R.DEVICE_REVOKED]


def test_revoke_requires_admin_token(env):
    phone = env.phone()
    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": ADMIN}):
        r = env.client.post(f"/v1/admin/devices/{phone.device_id}/revoke", json={"reason": "x"}, headers=headers)
        assert r.status_code == 401
    assert env.registry.get(phone.device_id).active


def test_revoke_endpoint_absent_without_admin_token(policy, env):
    client = TestClient(create_app(env.service))
    assert client.post("/v1/admin/devices/dev_x/revoke", json={"reason": "x"},
                       headers={"Authorization": f"Bearer {ADMIN}"}).status_code == 404


def test_unknown_device(env):
    assert env.action_challenge("dev_nope").status_code == 404
    fake = Phone("dev_nope", ec.generate_private_key(ec.SECP256R1()), None)
    ch = {"challengeId": "c", "nonce": "n"}
    assert env.verify(env.sign(fake, challenge=ch))["reasons"] == [R.DEVICE_UNKNOWN]


# --- Play Integrity per action ------------------------------------------------

def test_play_integrity_required_for_action(policy):
    env = Env(policy, decoder=EchoDecoder(), play_integrity_required_actions=frozenset({"payment"}))
    phone = env.phone()
    assert env.verify(env.sign(phone, "payment"))["reasons"] == [R.PLAY_INTEGRITY_MISSING]
    assert env.verify(env.sign(phone, "payment", play=True))["decision"] == "ALLOW"


def test_play_token_for_other_action_rejected(policy):
    env = Env(policy, decoder=EchoDecoder(), play_integrity_required_actions=frozenset({"payment"}))
    phone = env.phone()
    body = env.sign(phone, "payment", {"amountCents": 1})
    body["playIntegrityToken"] = action_request_hash(b"a different action")
    assert env.verify(body)["reasons"] == [R.PLAY_INTEGRITY_REQUEST_MISMATCH]


def test_play_device_integrity_failure_on_action_blocks(policy):
    env = Env(policy, decoder=EchoDecoder(verdicts=["MEETS_BASIC_INTEGRITY"]))
    phone = env.phone()
    assert env.verify(env.sign(phone, play=True))["reasons"] == [R.PLAY_DEVICE_INTEGRITY_FAILED]


# --- registry migration --------------------------------------------------------

def test_phase1_database_is_migrated_in_place(tmp_path):
    path = tmp_path / "devices.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE devices (device_id TEXT PRIMARY KEY, public_key_spki BLOB NOT NULL,"
        " spki_sha256 TEXT NOT NULL UNIQUE, enrolled_at INTEGER NOT NULL, evidence_json TEXT NOT NULL,"
        " play_signals_json TEXT);"
        "INSERT INTO devices VALUES ('dev_old', x'00', 'h', 1, '{}', NULL);"
    )
    conn.commit()
    conn.close()
    record = DeviceRegistry(path).get("dev_old")
    assert record.active and record.confirm_key_spki is None


def test_policy_rejects_inconsistent_action_sets(policy):
    with pytest.raises(ValueError):
        dataclasses.replace(policy, allowed_action_types=frozenset({"login"}),
                            confirm_key_required_actions=frozenset({"payment"})).validate()
