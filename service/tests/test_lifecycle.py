"""Run 16: device lifecycle, ownership and registry migrations."""

import dataclasses
import sqlite3

import pytest
from fastapi.testclient import TestClient
from test_actions import ADMIN, Env

from device_trust import reasons as R
from device_trust import registry as registry_module
from device_trust.api import create_app
from device_trust.lifecycle import Principal, owns
from device_trust.registry import SCHEMA_VERSION, DeviceRegistry, SchemaVersionError

GATEWAY = "g" * 40
ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN}"}
# Scam-call indicators score 70: STEP_UP at enrollment.
STEP_UP_SIGNALS = {"v": 1, "env_in_call": True, "env_remote_access_a11y": True}


class AsPrincipal:
    """TestClient wrapper that behaves like the customer's authenticated gateway."""

    def __init__(self, client, tenant="bank", account="alice", token=GATEWAY):
        self._client = client
        self.headers = {"X-Gateway-Authorization": f"Bearer {token}", "X-Tenant-Id": tenant, "X-Account-Id": account}

    def post(self, url, **kw):
        return self._client.post(url, headers={**self.headers, **kw.pop("headers", {})}, **kw)

    def get(self, url, **kw):
        return self._client.get(url, headers={**self.headers, **kw.pop("headers", {})}, **kw)


def gateway_env(policy, **overrides):
    env = Env(policy, **overrides)
    env.app_client = TestClient(create_app(env.service, expose_reasons=True, admin_token=ADMIN, gateway_token=GATEWAY))
    env.client = AsPrincipal(env.app_client)
    return env


def act_as(env, tenant="bank", account="alice"):
    env.client = AsPrincipal(env.app_client, tenant, account)
    return env


def complete(client, device_id, method="OTP"):
    return client.post(f"/v1/devices/{device_id}/step-up-completion", json={"method": method})


# --- states and transitions ---------------------------------------------------

def test_allow_enrollment_is_active_and_step_up_enrollment_is_pending(policy):
    env = Env(policy)
    data, phone = env.enroll()
    assert data["decision"] == "ALLOW" and data["deviceStatus"] == "active"
    step, pending = env.enroll(signals=STEP_UP_SIGNALS)
    assert step["decision"] == "STEP_UP" and step["deviceStatus"] == "pending"
    assert env.registry.get(pending.device_id).status == "pending"


def test_pending_device_cannot_act_until_authorised_completion(policy):
    env = Env(policy)
    _, phone = env.enroll(signals=STEP_UP_SIGNALS)
    assert env.action_challenge(phone.device_id).status_code == 404
    # Even with a challenge obtained some other way, the service refuses the action.
    challenge = env.service._challenges.issue(bound_to=phone.device_id)
    from device_trust.play_integrity import b64url
    body = env.sign(phone, challenge={"challengeId": challenge.challenge_id, "nonce": b64url(challenge.nonce)})
    assert env.verify(body)["reasons"] == [R.DEVICE_PENDING]
    # Completion needs authentication.
    assert env.client.post(f"/v1/admin/devices/{phone.device_id}/step-up-completion",
                           json={"method": "OTP"}).status_code == 401
    assert env.client.post(f"/v1/admin/devices/{phone.device_id}/step-up-completion",
                           json={"method": "OTP"}, headers=ADMIN_HEADERS).status_code == 204
    assert env.registry.get(phone.device_id).status == "active"
    assert env.verify(env.sign(phone))["decision"] == "ALLOW"
    # Completing twice is refused; unknown methods are rejected.
    assert env.client.post(f"/v1/admin/devices/{phone.device_id}/step-up-completion",
                           json={"method": "OTP"}, headers=ADMIN_HEADERS).status_code == 409
    assert env.client.post(f"/v1/admin/devices/{phone.device_id}/step-up-completion",
                           json={"method": "TRUST_ME"}, headers=ADMIN_HEADERS).status_code == 422


def test_revoked_is_terminal_and_reenrollment_never_revives_it(policy):
    env = Env(policy)
    data, phone = env.enroll(signals=STEP_UP_SIGNALS)
    assert env.service.revoke_device(phone.device_id, "test")
    assert env.service.complete_step_up(phone.device_id, "OTP", actor="admin") == "not_pending"
    assert env.service.revoke_device(phone.device_id, "again")  # idempotent
    assert env.registry.get(phone.device_id).status == "revoked"
    # Same attested key again: refused, the revoked record stays revoked.
    ch = env.client.post("/v1/challenges").json()
    from attestation_factory import DEVICE_IDS, KD, chain_der, make_leaf
    import base64
    nonce = base64.urlsafe_b64decode(ch["nonce"] + "==")
    leaf, _ = make_leaf(env.pki, KD(challenge=nonce), leaf_key=phone.device_key)
    again = env.client.post("/v1/enrollments", json={
        "challengeId": ch["challengeId"], "device": DEVICE_IDS,
        "attestationChain": [base64.b64encode(c).decode() for c in chain_der(leaf, env.pki.inter, env.pki.root)]}).json()
    assert again["decision"] == "BLOCK" and again["reasons"] == [R.KEY_ALREADY_ENROLLED]
    assert "deviceStatus" not in again
    assert env.registry.get(phone.device_id).status == "revoked"
    # A new key (reinstall / key loss) is a new device, not the old identity.
    fresh = env.phone()
    assert fresh.device_id != phone.device_id
    events = env.registry.lifecycle_events(phone.device_id)
    assert [e["event"] for e in events] == ["revoked", "enrolled"]


def test_pending_enrollment_expires(policy):
    clock = [1_000_000.0]
    env = Env(policy)
    env.registry._clock = lambda: clock[0]
    _, phone = env.enroll(signals=STEP_UP_SIGNALS)
    clock[0] += policy.pending_ttl_seconds + 1
    assert env.service.complete_step_up(phone.device_id, "OTP", actor="admin") == "expired"
    assert env.registry.get(phone.device_id).status == "revoked"
    assert env.registry.lifecycle_events(phone.device_id)[0]["event"] == "pending_expired"


def test_lifecycle_events_are_bounded(policy):
    env = Env(policy)
    _, phone = env.enroll(signals=STEP_UP_SIGNALS)
    env.service.complete_step_up(phone.device_id, "SUPPORT_VERIFIED", actor="admin")
    for event in env.registry.lifecycle_events(phone.device_id):
        assert set(event) == {"event", "from", "to", "actor", "reason", "at"}
        assert event["actor"] in {"system", "gateway", "admin"}
        assert event["reason"] is None or len(event["reason"]) <= 64
    detail = env.client.get(f"/v1/admin/devices/{phone.device_id}", headers=ADMIN_HEADERS).json()
    assert detail["status"] == "active" and detail["lifecycle"][0]["event"] == "step_up_completed"


# --- principals and ownership ---------------------------------------------------

def test_principal_rules():
    alice = Principal("bank", "alice")
    assert owns(alice, "bank", "alice")
    assert not owns(alice, "other-bank", "alice")       # tenant isolation
    assert not owns(alice, None, None)                  # a principal never claims an ownerless device
    assert owns(None, None, None) and not owns(None, "bank", "alice")
    with pytest.raises(ValueError):
        Principal("bank", "alice; DROP TABLE")


def test_gateway_requires_its_secret(policy):
    env = gateway_env(policy)
    assert env.app_client.post("/v1/challenges").status_code == 401
    assert AsPrincipal(env.app_client, token="wrong").post("/v1/challenges").status_code == 401
    assert AsPrincipal(env.app_client, account="").post("/v1/challenges").status_code == 400


def test_client_supplied_account_headers_are_ignored_without_gateway(policy):
    env = Env(policy)
    env.client.headers.update({"X-Account-Id": "mallory", "X-Tenant-Id": "bank"})
    phone = env.phone()
    record = env.registry.get(phone.device_id)
    assert record.owner_account is None and record.owner_tenant is None


def test_devices_are_owned_and_isolated(policy):
    env = gateway_env(policy)
    data, phone = env.enroll(signals=STEP_UP_SIGNALS)
    record = env.registry.get(phone.device_id)
    assert (record.owner_tenant, record.owner_account, record.binding) == ("bank", "alice", "LEGACY_UNBOUND")
    alice = env.client
    bob = AsPrincipal(env.app_client, account="bob")
    other_tenant = AsPrincipal(env.app_client, tenant="other-bank")
    for stranger in (bob, other_tenant):
        assert stranger.get(f"/v1/devices/{phone.device_id}").status_code == 404
        assert complete(stranger, phone.device_id).status_code == 404
        assert stranger.post(f"/v1/devices/{phone.device_id}/revoke", json={"reason": "LOST"}).status_code == 404
    status = alice.get(f"/v1/devices/{phone.device_id}").json()
    assert status == {"deviceId": phone.device_id, "status": "pending", "binding": "LEGACY_UNBOUND",
                      "hasConfirmKey": False}
    assert complete(alice, phone.device_id).json()["status"] == "active"
    assert env.verify(env.sign(phone))["decision"] == "ALLOW"
    # Bob cannot get a challenge for, or act as, Alice's device.
    act_as(env, account="bob")
    assert env.action_challenge(phone.device_id).status_code == 404
    act_as(env, account="alice")
    body = env.sign(phone)
    act_as(env, account="bob")
    assert env.verify(body)["reasons"] == [R.DEVICE_UNKNOWN]
    # The owner can revoke a lost phone.
    act_as(env, account="alice")
    assert env.client.post(f"/v1/devices/{phone.device_id}/revoke", json={"reason": "LOST"}).status_code == 204
    assert env.registry.get(phone.device_id).status == "revoked"


def test_enrollment_challenge_is_bound_to_the_principal(policy):
    env = gateway_env(policy)
    ch = env.client.post("/v1/challenges").json()
    act_as(env, account="bob")
    from attestation_factory import DEVICE_IDS, KD, chain_der, make_leaf
    import base64
    leaf, _ = make_leaf(env.pki, KD(challenge=base64.urlsafe_b64decode(ch["nonce"] + "==")))
    out = env.client.post("/v1/enrollments", json={
        "challengeId": ch["challengeId"], "device": DEVICE_IDS,
        "attestationChain": [base64.b64encode(c).decode() for c in chain_der(leaf, env.pki.inter, env.pki.root)]}).json()
    assert out["reasons"] == [R.CHALLENGE_UNKNOWN]


def test_require_principal_refuses_anonymous_requests(policy):
    env = Env(policy, require_principal=True)
    data, _ = env.enroll()
    assert data["decision"] == "BLOCK" and data["reasons"] == [R.PRINCIPAL_REQUIRED]


def test_unbound_enrollments_can_be_held_pending_and_quarantined(policy):
    env = Env(policy, unbound_enrollment_state="pending")
    data, phone = env.enroll()
    assert data["decision"] == "ALLOW" and data["deviceStatus"] == "pending"
    assert R.ENROLLMENT_LEGACY_UNBOUND in data["warnings"]

    legacy = Env(policy)
    old = legacy.phone()                      # active but LEGACY_UNBOUND
    legacy.service.policy = dataclasses.replace(legacy.policy, require_bound_device=True)
    assert legacy.verify(legacy.sign(old))["reasons"] == [R.DEVICE_REBINDING_REQUIRED]


def test_policy_validation(policy):
    with pytest.raises(ValueError):
        dataclasses.replace(policy, unbound_enrollment_state="maybe").validate()
    with pytest.raises(ValueError):
        dataclasses.replace(policy, pending_ttl_seconds=0).validate()
    with pytest.raises(ValueError):
        dataclasses.replace(policy, require_principal="yes").validate()


# --- migrations -------------------------------------------------------------------

def _phase1_db(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE devices (device_id TEXT PRIMARY KEY, public_key_spki BLOB NOT NULL,"
        " spki_sha256 TEXT NOT NULL UNIQUE, enrolled_at INTEGER NOT NULL, evidence_json TEXT NOT NULL,"
        " play_signals_json TEXT);"
        "INSERT INTO devices VALUES ('dev_old', x'00', 'h', 1, '{}', NULL);"
    )
    conn.commit()
    conn.close()


def _run22_db(path):
    """A database written by Run 13/22 code: user_version 0, snapshots present."""
    conn = sqlite3.connect(path)
    for statement in registry_module._BASE_SCHEMA.split(";"):
        if statement.strip():
            conn.execute(statement)
    registry_module._add_columns(conn, "devices", registry_module._LEGACY_COLUMNS)
    conn.execute("INSERT INTO devices (device_id, public_key_spki, spki_sha256, enrolled_at, evidence_json, status)"
                 " VALUES ('dev_r22', x'01', 'k', 2, '{}', 'revoked')")
    conn.execute("INSERT INTO assurance_snapshots VALUES ('dev_r22', '{\"v\":1}', 3.0)")
    conn.commit()
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
    conn.close()


def test_fresh_database_gets_current_schema(tmp_path):
    reg = DeviceRegistry(tmp_path / "fresh.sqlite")
    assert reg.schema_version() == SCHEMA_VERSION == 3  # Run 17 added migration 3


def test_phase1_database_is_adopted_and_upgraded(tmp_path):
    path = tmp_path / "p1.sqlite"
    _phase1_db(path)
    reg = DeviceRegistry(path)
    record = reg.get("dev_old")
    assert reg.schema_version() == SCHEMA_VERSION
    assert record.status == "active" and record.binding == "UNKNOWN" and record.owner_account is None


def test_run22_database_keeps_rows_and_snapshots(tmp_path):
    path = tmp_path / "r22.sqlite"
    _run22_db(path)
    reg = DeviceRegistry(path)
    assert reg.get("dev_r22").status == "revoked"
    assert reg.assurance_history("dev_r22")[0]["evidence"] == {"v": 1}
    # Repeat startup is a no-op.
    again = DeviceRegistry(path)
    assert again.schema_version() == SCHEMA_VERSION and again.get("dev_r22").status == "revoked"


def test_failed_migration_rolls_back_completely(tmp_path, monkeypatch):
    path = tmp_path / "rb.sqlite"
    _phase1_db(path)

    def broken(conn):
        registry_module._migrate_2_lifecycle(conn)   # DDL succeeds...
        raise RuntimeError("disk full")              # ...then the step fails

    monkeypatch.setattr(registry_module, "MIGRATIONS", ((1, registry_module._migrate_1_adopt), (2, broken)))
    with pytest.raises(RuntimeError):
        DeviceRegistry(path)
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    columns = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
    assert "owner_account" not in columns and "status" in columns
    assert conn.execute("SELECT name FROM sqlite_master WHERE name='lifecycle_events'").fetchone() is None
    conn.close()
    monkeypatch.undo()
    assert DeviceRegistry(path).get("dev_old").status == "active"


def test_newer_schema_is_refused(tmp_path):
    path = tmp_path / "new.sqlite"
    DeviceRegistry(path)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA user_version = 99")
    conn.commit()
    conn.close()
    with pytest.raises(SchemaVersionError):
        DeviceRegistry(path)
