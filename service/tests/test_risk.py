"""Phase 3: client signals, risk scoring and the decision audit trail."""

import dataclasses
import sqlite3
from datetime import datetime, timezone

import pytest
from attestation_factory import SIGNING_DIGEST
from test_actions import ADMIN, EchoDecoder, Env

from device_trust import reasons as R
from device_trust.policy import TrustPolicy
from device_trust.risk import (
    ALLOW,
    BLOCK,
    DEFAULT_WEIGHTS,
    STEP_UP,
    RiskInput,
    RiskPolicy,
    Thresholds,
    assess,
)
from device_trust.signals import SignalsError, parse_client_signals

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)
DIGEST = "ab" * 32
CLEAN = {"v": 1, "root_su": False, "hook_frida": False, "app_installer": "com.android.vending",
         "app_signature_sha256": DIGEST, "env_a11y_third_party": 0, "env_remote_access_apps": []}


def score(signals=None, play=None, evidence=None, action="login", policy=RiskPolicy(), **kw):
    client = parse_client_signals(signals) if signals is not None else None
    return assess(RiskInput(client, play, evidence, **kw), policy, frozenset({DIGEST}), action, NOW)


# --- signal parsing -------------------------------------------------------------

def test_clean_report_parses_and_scores_zero():
    result = score(CLEAN)
    assert result.score == 0 and result.band == ALLOW and result.factors == ()


@pytest.mark.parametrize(
    "bad",
    [
        None, [], {"v": 2}, {"v": True}, {"root_su": True},
        {"v": 1, "root_su": "yes"},
        {"v": 1, "root_su": 1},
        {"v": 1, "env_a11y_third_party": -1},
        {"v": 1, "env_a11y_third_party": True},
        {"v": 1, "app_installer": 5},
        {"v": 1, "app_installer": "x" * 200},
        {"v": 1, "env_remote_access_apps": "anydesk"},
        {"v": 1, "env_remote_access_apps": ["has space"]},
        {"v": 1, "env_remote_access_apps": ["a"] * 33},
    ],
)
def test_invalid_reports_rejected(bad):
    with pytest.raises(SignalsError):
        parse_client_signals(bad)


def test_unknown_signal_keys_are_ignored_for_forward_compatibility():
    assert parse_client_signals({"v": 1, "future_signal": True, "root_su": True}) == {"root_su": True}


# --- scoring -----------------------------------------------------------------------

def test_factors_are_explained_and_sorted_by_weight():
    result = score({**CLEAN, "hook_frida": True, "env_dev_options": True})
    assert result.factors == (("hook_frida", 70), ("env_dev_options", 5))
    assert result.score == 75 and result.band == STEP_UP


def test_score_is_capped_at_100():
    result = score({**CLEAN, "hook_frida": True, "hook_xposed": True, "emu_build": True})
    assert result.score == 100 and result.band == BLOCK


def test_missing_report_is_a_factor():
    assert score(None).factors == (("client_signals_missing", 20),)


@pytest.mark.parametrize(
    "signals, factor",
    [
        ({"app_installer": "com.sideload.store"}, "app_installer_untrusted"),
        ({"app_installer": None}, "app_installer_untrusted"),
        ({"app_signature_sha256": "cd" * 32}, "app_signature_mismatch"),
        ({"env_a11y_third_party": 2}, "env_a11y_third_party"),
        ({"env_remote_access_apps": ["anydesk"]}, "env_remote_access_apps"),
        ({"env_in_call": True}, "env_in_call"),
        ({"env_remote_access_a11y": True}, "env_remote_access_a11y"),
    ],
)
def test_client_derived_factors(signals, factor):
    assert factor in score({**CLEAN, **signals}).factor_names()


def test_signature_digest_comparison_ignores_case_and_colons():
    colon = ":".join(DIGEST[i:i + 2] for i in range(0, 64, 2)).upper()
    assert "app_signature_mismatch" not in score({**CLEAN, "app_signature_sha256": colon}).factor_names()


@pytest.mark.parametrize(
    "play, expected",
    [
        ({"device_recognition": ["MEETS_DEVICE_INTEGRITY"]}, {"play_no_strong_integrity"}),
        ({"device_recognition": ["MEETS_STRONG_INTEGRITY"], "app_access_risk": ["UNKNOWN_CONTROLLING"]},
         {"play_controlling_apps"}),
        ({"device_recognition": ["MEETS_STRONG_INTEGRITY"], "app_access_risk": ["KNOWN_CAPTURING", "KNOWN_OVERLAYS"]},
         {"play_capturing_apps", "play_overlay_apps"}),
        ({"device_recognition": ["MEETS_STRONG_INTEGRITY"], "play_protect": "HIGH_RISK"}, {"play_protect_high_risk"}),
        ({"device_recognition": ["MEETS_STRONG_INTEGRITY"], "device_activity_level": "LEVEL_4"},
         {"play_activity_level_4"}),
        ({"device_recognition": ["MEETS_STRONG_INTEGRITY"], "app_licensing": "UNLICENSED"}, {"play_unlicensed"}),
        ({"device_recognition": ["MEETS_STRONG_INTEGRITY"], "app_access_risk": ["KNOWN_INSTALLED"],
          "play_protect": "NO_ISSUES", "device_activity_level": "LEVEL_1"}, set()),
    ],
)
def test_play_integrity_factors(play, expected):
    assert set(score(CLEAN, play=play).factor_names()) == expected


def test_hardware_evidence_and_history_factors():
    evidence = {"os_patch_level": 202501, "attestation_security_level": "TRUSTED_ENVIRONMENT"}
    names = score(CLEAN, evidence=evidence, device_age_seconds=60, recent_actions=30).factor_names()
    assert {"os_patch_stale", "no_strongbox", "device_new", "velocity_high"} <= set(names)
    fresh = {"os_patch_level": 20260905, "attestation_security_level": "STRONG_BOX"}
    assert score(CLEAN, evidence=fresh, device_age_seconds=10**6, recent_actions=1).factors == ()


def test_per_action_thresholds():
    policy = RiskPolicy(action_thresholds={"payment": Thresholds(allow_below=10, block_at=40)})
    signals = {**CLEAN, "env_in_call": True}  # 25 points
    assert score(signals, action="login", policy=policy).band == ALLOW
    assert score(signals, action="payment", policy=policy).band == STEP_UP


def test_enrollment_uses_enrollment_thresholds():
    signals = {**CLEAN, "env_in_call": True, "env_external_display": True}  # 55
    assert score(signals, action="login").band == STEP_UP
    assert score(signals, action=None).band == ALLOW


# --- policy loading --------------------------------------------------------------------

def test_risk_policy_from_dict_merges_weights():
    policy = RiskPolicy.from_dict({"weights": {"env_vpn": 0, "env_in_call": 60},
                                   "action_thresholds": {"payment": {"allow_below": 20, "block_at": 60}}})
    assert policy.weights["env_vpn"] == 0 and policy.weights["env_in_call"] == 60
    assert policy.weights["hook_frida"] == DEFAULT_WEIGHTS["hook_frida"]
    assert policy.thresholds_for("payment") == Thresholds(20, 60)


@pytest.mark.parametrize(
    "raw",
    [
        {"weights": {"made_up": 5}},
        {"weights": {"env_vpn": -1}},
        {"default_thresholds": {"allow_below": 80, "block_at": 50}},
        {"default_thresholds": {"allow_below": 0, "block_at": 50}},
        {"surprise": 1},
    ],
)
def test_risk_policy_rejects_bad_config(raw):
    with pytest.raises((ValueError, TypeError)):
        RiskPolicy.from_dict(raw)


def test_trust_policy_loads_risk_section():
    policy = TrustPolicy.from_dict({"package_name": "p", "signing_cert_sha256": [DIGEST],
                                    "risk": {"velocity_max_actions": 5}})
    assert policy.risk.velocity_max_actions == 5


# Same report, but carrying the signing digest the end-to-end policy trusts.
E2E = {**CLEAN, "app_signature_sha256": SIGNING_DIGEST.hex()}


# --- end to end ------------------------------------------------------------------------

@pytest.fixture
def env(policy):
    return Env(policy)


def test_clean_signed_signals_allow(env):
    phone = env.phone(signals={**E2E, "app_signature_sha256": None})
    out = env.verify(env.sign(phone, overrides={"signals": {**E2E, "app_signature_sha256": None}}))
    assert out["decision"] == "ALLOW", out
    # no_strongbox is informational (weight 0) but still listed for the fraud team.
    coverage = out["risk"].pop("coverage")
    assert out["risk"] == {"score": 10, "factors": [{"factor": "device_new", "points": 10},
                                                    {"factor": "no_strongbox", "points": 0}]}
    # A pre-Run-14 client reports no check states: nothing is assumed complete.
    assert coverage["UNREPORTED"] == 22 and coverage["NOT_DETECTED"] == 0


def test_frida_detected_blocks_action(env):
    phone = env.phone()
    out = env.verify(env.sign(phone, overrides={"signals": {**E2E, "hook_frida": True}}))
    assert out["decision"] == "BLOCK" and out["reasons"] == [R.RISK_BLOCK]
    assert out["risk"]["factors"][0] == {"factor": "hook_frida", "points": 70}
    assert "action" not in out


def test_scam_call_with_remote_control_steps_up(env):
    phone = env.phone()
    signals = {**E2E, "env_in_call": True, "env_remote_access_apps": ["anydesk"]}  # 25 + 15 + device_new 10
    out = env.verify(env.sign(phone, "payment", overrides={"signals": signals}))
    assert out["decision"] == "STEP_UP" and out["reasons"] == [R.RISK_STEP_UP]
    assert out["risk"]["score"] == 50


def test_hard_gate_beats_risk(env):
    """A clean risk score never rescues a bad signature."""
    from cryptography.hazmat.primitives.asymmetric import ec

    phone = env.phone()
    out = env.verify(env.sign(phone, overrides={"signals": E2E}, signer=ec.generate_private_key(ec.SECP256R1())))
    assert out["decision"] == "BLOCK" and R.SIGNATURE_INVALID in out["reasons"]


def test_confirm_key_step_up_and_risk_step_up_stay_step_up(policy):
    env = Env(policy, confirm_key_required_actions=frozenset({"payment"}))
    phone = env.phone()
    out = env.verify(env.sign(phone, "payment", overrides={"signals": {**E2E, "env_in_call": True,
                                                                         "env_remote_access_apps": ["x"]}}))
    assert out["decision"] == "STEP_UP"
    assert set(out["reasons"]) == {R.CONFIRM_KEY_REQUIRED, R.RISK_STEP_UP}


@pytest.mark.parametrize("bad", [{"v": 9}, "nope", {"v": 1, "root_su": "true"}])
def test_malformed_signals_in_signed_action_block(env, bad):
    phone = env.phone()
    out = env.verify(env.sign(phone, overrides={"signals": bad}))
    assert out["decision"] == "BLOCK" and R.SIGNALS_MALFORMED in out["reasons"]


def test_velocity_limit(policy):
    env = Env(policy, risk=RiskPolicy(velocity_max_actions=3, weights={**DEFAULT_WEIGHTS, "velocity_high": 60}))
    phone = env.phone()
    decisions = [env.verify(env.sign(phone, overrides={"signals": E2E}))["decision"] for _ in range(4)]
    assert decisions == ["ALLOW", "ALLOW", "ALLOW", "STEP_UP"]


def test_emulator_enrollment_blocked_and_not_registered(env):
    data, _ = env.enroll(signals={**E2E, "emu_build": True, "emu_files": True})
    assert data["decision"] == "BLOCK" and data["reasons"] == [R.RISK_BLOCK]
    assert "deviceId" not in data
    assert env.registry.count() == 0


def test_risky_enrollment_steps_up_but_registers(env):
    data, _ = env.enroll(signals={**E2E, "root_magisk": True, "env_adb": True})  # 60
    assert data["decision"] == "STEP_UP" and data["reasons"] == [R.RISK_STEP_UP]
    assert data["deviceId"] and env.registry.count() == 1


def test_malformed_enrollment_signals_block(env):
    data, _ = env.enroll(signals={"v": 1, "hook_frida": "no"})
    assert data["decision"] == "BLOCK" and R.SIGNALS_MALFORMED in data["reasons"]


def test_play_signals_feed_action_risk(policy):
    env = Env(policy, decoder=EchoDecoder(verdicts=["MEETS_DEVICE_INTEGRITY"]))
    phone = env.phone()
    out = env.verify(env.sign(phone, overrides={"signals": E2E}, play=True))
    assert {"factor": "play_no_strong_integrity", "points": 10} in out["risk"]["factors"]


def test_admin_device_detail_shows_decisions_without_params(env):
    phone = env.phone()
    env.verify(env.sign(phone, "payment", {"iban": "NL91ABNA0417164300"},
                        overrides={"signals": {**E2E, "hook_frida": True}}))
    r = env.client.get(f"/v1/admin/devices/{phone.device_id}", headers={"Authorization": f"Bearer {ADMIN}"})
    assert r.status_code == 200
    detail = r.json()
    assert detail["status"] == "active" and detail["attested"]["model"] == "SM-S928B"
    latest = detail["decisions"][0]
    assert latest["kind"] == "action" and latest["actionType"] == "payment" and latest["decision"] == "BLOCK"
    assert latest["factors"][0] == {"factor": "hook_frida", "points": 70}
    assert detail["decisions"][-1]["kind"] == "enrollment"
    dump = "\n".join(env.registry._conn.iterdump())
    assert "NL91ABNA0417164300" not in dump


def test_admin_device_detail_requires_token(env):
    phone = env.phone()
    assert env.client.get(f"/v1/admin/devices/{phone.device_id}").status_code == 401
    assert env.client.get("/v1/admin/devices/dev_missing",
                          headers={"Authorization": f"Bearer {ADMIN}"}).status_code == 404


def test_risk_hidden_from_clients_by_default(env):
    from fastapi.testclient import TestClient

    from device_trust.api import create_app

    phone = env.phone()
    body = env.sign(phone, overrides={"signals": {**E2E, "hook_frida": True}})
    out = TestClient(create_app(env.service)).post("/v1/actions/verify", json=body).json()
    assert out["decision"] == "BLOCK" and "risk" not in out and "reasons" not in out


def test_decisions_table_migrates_existing_database(tmp_path):
    path = tmp_path / "d.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE devices (device_id TEXT PRIMARY KEY, public_key_spki BLOB NOT NULL,"
        " spki_sha256 TEXT NOT NULL UNIQUE, enrolled_at INTEGER NOT NULL, evidence_json TEXT NOT NULL,"
        " play_signals_json TEXT);"
    )
    conn.close()
    from device_trust.registry import DeviceRegistry

    reg = DeviceRegistry(path)
    reg.record_decision("dec_1", "dev_1", "action", "login", "ALLOW", 0, [], [])
    assert reg.count_recent_actions("dev_1", 60) == 1
