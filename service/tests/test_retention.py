"""Run 29: retention sweep, erasure and their safety properties."""

import dataclasses
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from test_actions import ADMIN, Env
from test_lifecycle import STEP_UP_SIGNALS, AsPrincipal, gateway_env
from test_verified_scan import device_challenge, rotate, rotation_body, scan, scan_body

from device_trust import reasons as R
from device_trust.policy import TrustPolicy

DAY = 86400
ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN}"}


def clocked_env(policy, **overrides):
    clock = [1_800_000_000.0]
    env = Env(policy, **overrides)
    env.registry._clock = lambda: clock[0]
    return env, clock


def table_count(env, table, device_id=None):
    sql = f"SELECT COUNT(*) FROM {table}" + (" WHERE device_id = ?" if device_id else "")
    return env.registry._conn.execute(sql, (device_id,) if device_id else ()).fetchone()[0]


# --- policy ------------------------------------------------------------------

def test_defaults_are_valid_and_cover_risk_windows(policy):
    policy.validate()
    assert policy.retention_fleet_events_days * DAY >= policy.risk.fleet_window_seconds
    assert policy.retention_key_uses_days * DAY >= policy.risk.keybox_window_seconds
    assert policy.retention_decisions_days * DAY >= policy.risk.velocity_window_seconds


@pytest.mark.parametrize("change", [
    {"retention_key_uses_days": 7},          # shorter than the 30-day keybox window
    {"retention_decisions_days": 0},
    {"retention_fleet_events_days": "30"},
])
def test_retention_shorter_than_a_risk_window_or_invalid_is_rejected(policy, change):
    with pytest.raises(ValueError):
        dataclasses.replace(policy, **change).validate()


# --- sweep -------------------------------------------------------------------

def test_sweep_deletes_only_rows_past_retention(policy):
    env, clock = clocked_env(policy)
    phone = env.phone()
    env.verify(env.sign(phone))
    scan(env, scan_body(env, phone))
    assert table_count(env, "decisions") == 3            # enrollment, action, scan
    assert table_count(env, "assurance_snapshots") == 2  # enrollment + refresh
    # Nothing is old yet.
    assert set(env.service.retention_sweep(clock[0]).values()) == {0}
    # Past every retention period.
    clock[0] += 800 * DAY
    out = env.service.retention_sweep(clock[0])
    assert out["decisions"] == 3 and out["fleet_events"] >= 2 and out["attestation_key_uses"] == 1
    assert out["lifecycle_events"] == 1 and out["scan_snapshots"] == 1
    # The device record and its enrollment snapshot survive: they anchor continuity and
    # stop the same key from enrolling again.
    record = env.registry.get(phone.device_id)
    assert record is not None and record.status == "active"
    sources = [h["evidence"]["source"] for h in env.registry.assurance_history(phone.device_id, 100)]
    assert sources == ["enrollment"]


def test_risk_windows_still_see_recent_rows_after_a_sweep(policy):
    env, clock = clocked_env(policy, risk=dataclasses.replace(policy.risk, velocity_max_actions=2))
    phone = env.phone()
    env.verify(env.sign(phone))
    env.service.retention_sweep(clock[0] + 60)
    assert env.registry.count_recent_actions(phone.device_id, policy.risk.velocity_window_seconds) == 1


def test_sweep_expires_forgotten_pending_enrollments(policy):
    env, clock = clocked_env(policy)
    _, pending = env.enroll(signals=STEP_UP_SIGNALS)
    _, active = env.enroll()
    clock[0] += policy.pending_ttl_seconds + 1
    out = env.service.retention_sweep(clock[0])
    assert out["pending_expired"] == 1
    assert env.registry.get(pending.device_id).status == "revoked"
    assert env.registry.get(active.device_id).status == "active"


def test_rotation_continuity_survives_scan_snapshot_retention(policy):
    env, clock = clocked_env(policy)
    phone = env.phone()
    body, new_key, _ = rotation_body(env, phone)
    assert rotate(env, body)["rotated"] is True
    clock[0] += 800 * DAY
    env.service.retention_sweep(clock[0])
    sources = [h["evidence"]["source"] for h in env.registry.assurance_history(phone.device_id, 100)]
    assert sources == ["key_rotation", "enrollment"]


# --- erasure -------------------------------------------------------------------

def test_admin_erasure_removes_device_data_and_blocks_re_enrollment(policy):
    env = Env(policy)
    phone = env.phone()
    env.verify(env.sign(phone))
    scan(env, scan_body(env, phone))
    assert env.client.delete(f"/v1/admin/devices/{phone.device_id}").status_code == 401
    assert env.client.delete(f"/v1/admin/devices/{phone.device_id}", headers=ADMIN_HEADERS).status_code == 204
    assert env.registry.get(phone.device_id) is None
    for table in ("assurance_snapshots", "decisions", "lifecycle_events", "fleet_events"):
        assert table_count(env, table, phone.device_id) == 0, table
    # Only an unlinked hash of the key remains, and it still blocks the key.
    tombstones = env.registry._conn.execute("SELECT device_id FROM retired_keys").fetchall()
    assert tombstones == [("erased",)]
    assert env.client.delete(f"/v1/admin/devices/{phone.device_id}", headers=ADMIN_HEADERS).status_code == 404
    data, _ = env.enroll(reuse_key=False)
    assert data["decision"] == "ALLOW"   # a new key enrolls normally
    from attestation_factory import DEVICE_IDS, KD, chain_der, make_leaf
    import base64
    ch = env.client.post("/v1/challenges").json()
    leaf, _ = make_leaf(env.pki, KD(challenge=base64.urlsafe_b64decode(ch["nonce"] + "==")), leaf_key=phone.device_key)
    again = env.client.post("/v1/enrollments", json={
        "challengeId": ch["challengeId"], "device": DEVICE_IDS,
        "attestationChain": [base64.b64encode(c).decode() for c in chain_der(leaf, env.pki.inter, env.pki.root)],
    }).json()
    assert again["reasons"] == [R.KEY_ALREADY_ENROLLED]


def test_erasure_after_rotation_unlinks_retired_keys(policy):
    env = Env(policy)
    phone = env.phone()
    body, _, _ = rotation_body(env, phone)
    assert rotate(env, body)["rotated"] is True
    assert env.service.erase_device(phone.device_id)
    rows = env.registry._conn.execute("SELECT device_id FROM retired_keys").fetchall()
    assert len(rows) == 2 and set(rows) == {("erased",)}


def test_owner_can_erase_own_device_and_account_only(policy):
    env = gateway_env(policy)
    _, alice1 = env.enroll()
    _, alice2 = env.enroll()
    bob_client = AsPrincipal(env.app_client, account="bob")
    env.client = bob_client
    _, bob_phone = env.enroll()
    other_tenant = AsPrincipal(env.app_client, tenant="other-bank", account="alice")
    alice = AsPrincipal(env.app_client)
    # Strangers get the same 404 as for an unknown device.
    for stranger in (bob_client, other_tenant):
        assert stranger._client.delete(f"/v1/devices/{alice1.device_id}", headers=stranger.headers).status_code == 404
    assert alice._client.delete(f"/v1/devices/{alice1.device_id}", headers=alice.headers).status_code == 204
    assert env.registry.get(alice1.device_id) is None
    out = alice._client.delete("/v1/account/data", headers=alice.headers)
    assert out.status_code == 200 and out.json() == {"erasedDevices": 1}
    assert env.registry.get(alice2.device_id) is None
    assert env.registry.get(bob_phone.device_id) is not None   # other accounts untouched
    # Without the gateway secret the erasure routes refuse.
    assert env.app_client.delete("/v1/account/data").status_code == 401


def test_admin_account_erasure(policy):
    env = gateway_env(policy)
    env.enroll()
    env.enroll()
    out = env.app_client.post("/v1/admin/accounts/erasure", json={"tenant": "bank", "account": "alice"},
                              headers=ADMIN_HEADERS)
    assert out.json() == {"erasedDevices": 2}
    assert env.app_client.post("/v1/admin/accounts/erasure", json={"tenant": "bank", "account": "x y"},
                               headers=ADMIN_HEADERS).status_code == 422


def test_admin_sweep_endpoint(policy):
    env = Env(policy)
    env.phone()
    out = env.client.post("/v1/admin/retention-sweep", headers=ADMIN_HEADERS).json()
    assert set(out) == {"pending_expired", "decisions", "fleet_events", "attestation_key_uses",
                        "lifecycle_events", "scan_snapshots"}


# --- migration and CLI ----------------------------------------------------------

def test_migration_4_adds_time_indexes(tmp_path):
    from device_trust.registry import DeviceRegistry
    reg = DeviceRegistry(tmp_path / "r.sqlite")
    names = {r[0] for r in reg._conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert {"decisions_created", "fleet_events_created", "attestation_key_uses_created",
            "lifecycle_events_created", "assurance_snapshots_source_time"} <= names
    plan = " ".join(r[3] for r in reg._conn.execute(
        "EXPLAIN QUERY PLAN DELETE FROM fleet_events WHERE created_at < 1"))
    assert "fleet_events_created" in plan


def test_purge_and_erase_cli(tmp_path, policy):
    db = tmp_path / "d.sqlite"
    pol = tmp_path / "policy.json"
    pol.write_text(json.dumps({"package_name": policy.package_name,
                               "signing_cert_sha256": sorted(policy.signing_cert_sha256)}))
    root = Path(__file__).resolve().parents[1]
    run = lambda *a: subprocess.run([sys.executable, "-m", "device_trust.cli", *a], cwd=root,
                                    capture_output=True, text=True, check=True).stdout
    out = json.loads(run("purge", "--policy", str(pol), "--db", str(db)))
    assert out["decisions"] == 0 and out["pending_expired"] == 0
    out = json.loads(run("erase-account", "--policy", str(pol), "--db", str(db), "--tenant", "bank",
                         "--account", "alice"))
    assert out == {"erasedDevices": 0}
