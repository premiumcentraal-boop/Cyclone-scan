"""Run 12: fleet intelligence (network/cohort bursts, device recall, admin view)."""

import dataclasses
import time

import pytest
from fastapi.testclient import TestClient
from test_actions import ADMIN, EchoDecoder, Env

from device_trust import reasons as R
from device_trust.api import create_app
from device_trust.fleet import NetworkHasher, cohort_key
from device_trust.play_integrity import evaluate_payload
from device_trust.policy import TrustPolicy
from device_trust.risk import RiskInput, RiskPolicy, assess

CLEAN = {"v": 1, "app_installer": "com.android.vending", "os_security_patch": "2026-09-05", "os_release": "13"}


# --- hashing -------------------------------------------------------------------------

def test_network_hash_groups_by_block_and_hides_the_address():
    h = NetworkHasher("k" * 32)
    a, b, c = h.network_key("203.0.113.7"), h.network_key("203.0.113.250"), h.network_key("203.0.114.7")
    assert a == b != c
    assert "203" not in a and len(a) == 32
    assert h.network_key("2001:db8:1:2::1") == h.network_key("2001:db8:1:ffff::9")
    assert h.network_key("::ffff:203.0.113.9") == a
    assert NetworkHasher("other-key" * 4).network_key("203.0.113.7") != a


@pytest.mark.parametrize("bad", [None, "", "testclient", "999.1.1.1", "not an ip"])
def test_invalid_addresses_are_ignored(bad):
    assert NetworkHasher("k" * 32).network_key(bad) is None


def test_cohort_key():
    ev = {"attested_ids": {"model": "SM-A556B"}, "os_patch_level": 202609, "chain_type": "FACTORY"}
    assert cohort_key(ev) == "sm-a556b|202609|FACTORY"
    assert cohort_key({"os_patch_level": 202609}, {"model": "X"}) == "x|202609|UNKNOWN"
    assert cohort_key({"attested_ids": {}}) is None


# --- risk factors ----------------------------------------------------------------------

def names(fleet=None, play=None, policy=RiskPolicy()):
    return assess(RiskInput({"v": 1}, play, None, fleet=fleet), policy, frozenset(), "login").factor_names()


def test_fleet_thresholds():
    assert "fleet_network_burst" in names({"network_enrollments": 10})
    assert "fleet_network_burst" not in names({"network_enrollments": 9})
    assert "fleet_cohort_burst" in names({"cohort_enrollments": 25})
    assert "fleet_network_many_devices" in names({"network_devices": 20})
    assert not {f for f in names({"network_enrollments": 1, "cohort_enrollments": 1, "network_devices": 1})
                if f.startswith("fleet_")}


def test_device_recall_bits():
    play = {"device_recognition": ["MEETS_STRONG_INTEGRITY"], "device_recall": {"bitFirst": True}}
    assert "fleet_device_recall_flagged" in names(play=play)
    assert "fleet_device_recall_flagged" not in names(play={**play, "device_recall": {"bitSecond": True}})
    custom = RiskPolicy(device_recall_fraud_bits=frozenset({"bitSecond"}))
    assert "fleet_device_recall_flagged" in names(play={**play, "device_recall": {"bitSecond": True}}, policy=custom)


def test_device_recall_parsed_from_play_payload(policy):
    payload = {"deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
                                   "deviceRecall": {"values": {"bitFirst": True, "bitSecond": False, "evil": True},
                                                    "writeDates": {"yyyymmFirst": 202609}}}}
    signals = evaluate_payload(payload, policy, "x", 0).signals
    assert signals["device_recall"] == {"bitFirst": True, "bitSecond": False}


def test_fleet_policy_loading():
    p = TrustPolicy.from_dict({"package_name": "p", "signing_cert_sha256": ["ab" * 32], "fleet_hash_key": "s" * 32,
                               "risk": {"fleet_network_enrollment_threshold": 3,
                                        "device_recall_fraud_bits": ["bitThird"]}})
    assert p.fleet_hash_key and p.risk.fleet_network_enrollment_threshold == 3
    with pytest.raises(ValueError):
        RiskPolicy.from_dict({"device_recall_fraud_bits": ["bitFourth"]})


# --- end to end ----------------------------------------------------------------------------

def env_with_ip(policy, ip, decoder=None, **risk_overrides):
    env = Env(policy, decoder=decoder, fleet_hash_key="k" * 32,
              risk=dataclasses.replace(RiskPolicy(), **risk_overrides))
    env.app = create_app(env.service, expose_reasons=True, admin_token=ADMIN, trust_forwarded_for=True)
    env.use_ip = lambda new_ip: setattr(env, "client", TestClient(env.app, headers={"X-Forwarded-For": new_ip}))
    env.use_ip(ip)
    return env


def test_enrollment_burst_from_one_network_is_flagged(policy):
    env = env_with_ip(policy, "203.0.113.10", fleet_network_enrollment_threshold=3,
                      fleet_cohort_enrollment_threshold=100)
    results = [env.enroll(signals=CLEAN)[0] for _ in range(3)]
    flagged = [any(f["factor"] == "fleet_network_burst" for f in r["risk"]["factors"]) for r in results]
    assert flagged == [False, False, True]
    env.use_ip("198.51.100.20")  # a different network block is unaffected
    other = env.enroll(signals=CLEAN)[0]
    assert not any(f["factor"] == "fleet_network_burst" for f in other["risk"]["factors"])


def test_cohort_burst_is_flagged_across_networks(policy):
    env = env_with_ip(policy, "203.0.113.10", fleet_cohort_enrollment_threshold=3,
                      fleet_network_enrollment_threshold=100)
    for i, ip in enumerate(["203.0.113.10", "198.51.100.20", "192.0.2.30"]):
        env.use_ip(ip)
        data = env.enroll(signals=CLEAN)[0]
    assert any(f["factor"] == "fleet_cohort_burst" for f in data["risk"]["factors"])


def test_many_devices_acting_from_one_network(policy):
    env = env_with_ip(policy, "203.0.113.10", fleet_network_device_threshold=3,
                      fleet_network_enrollment_threshold=100, fleet_cohort_enrollment_threshold=100)
    phones = []
    for ip in ["192.0.2.1", "192.0.3.1", "192.0.4.1"]:  # enrolled from different networks
        env.use_ip(ip)
        phones.append(env.phone(signals=CLEAN))
    env.use_ip("203.0.113.50")  # then all act from one network
    outs = [env.verify(env.sign(p, overrides={"signals": CLEAN})) for p in phones]
    assert not any(f["factor"] == "fleet_network_many_devices" for f in outs[0]["risk"]["factors"])
    assert any(f["factor"] == "fleet_network_many_devices" for f in outs[2]["risk"]["factors"])


def test_forwarded_header_ignored_unless_trusted(policy):
    env = Env(policy, fleet_hash_key="k" * 32,
              risk=dataclasses.replace(RiskPolicy(), fleet_network_enrollment_threshold=2))
    env.client = TestClient(create_app(env.service, expose_reasons=True), headers={"X-Forwarded-For": "203.0.113.9"})
    for _ in range(3):
        data = env.enroll(signals=CLEAN)[0]
    # "testclient" is not an IP, and the header is untrusted, so no network is recorded.
    assert not any(f["factor"] == "fleet_network_burst" for f in data["risk"]["factors"])


def test_device_recall_flag_blocks_actions(policy):
    class RecallDecoder(EchoDecoder):
        def decode(self, package_name, token):
            payload = super().decode(package_name, token)
            payload["deviceIntegrity"]["deviceRecall"] = {"values": {"bitFirst": True}}
            return payload

    env = env_with_ip(policy, "203.0.113.10", decoder=RecallDecoder(verdicts=["MEETS_STRONG_INTEGRITY"]))
    phone = env.phone(signals=CLEAN)
    out = env.verify(env.sign(phone, overrides={"signals": CLEAN}, play=True))
    assert out["decision"] == "BLOCK" and R.RISK_BLOCK in out["reasons"]
    assert {"factor": "fleet_device_recall_flagged", "points": 80} in out["risk"]["factors"]


def test_admin_fleet_view_shows_clusters_without_addresses(policy):
    env = env_with_ip(policy, "203.0.113.10")
    for _ in range(3):
        env.enroll(signals=CLEAN)
    r = env.client.get("/v1/admin/fleet", headers={"Authorization": f"Bearer {ADMIN}"})
    assert r.status_code == 200
    body = r.json()
    assert body["networks"][0]["enrollments"] == 3
    assert body["cohorts"][0]["enrollments"] == 3
    assert body["attestationKeys"][0]["enrollments"] == 3
    text = r.text + "\n".join(env.registry._conn.iterdump())
    assert "203.0.113" not in text
    assert env.client.get("/v1/admin/fleet").status_code == 401
