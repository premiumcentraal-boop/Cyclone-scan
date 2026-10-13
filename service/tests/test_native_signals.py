"""Native reports are low-trust evidence, strictly typed and not double-counted."""
import pytest
from device_trust.signals import parse_client_signals, SignalsError, NATIVE_BOOL_SIGNALS
from device_trust.risk import assess, RiskInput, RiskPolicy, NATIVE_ALIASES

def result(report):
    return assess(RiskInput(parse_client_signals({"v": 1, **report})), RiskPolicy(), frozenset(), "login")

@pytest.mark.parametrize("key,factor", list(NATIVE_ALIASES.items()))
def test_native_and_kotlin_evidence_share_one_factor(key, factor):
    native = {key: True, key + "_status": "DETECTED"}
    assert result(native).factor_names() == [factor]
    assert result({**native, factor: True}).factors == result(native).factors

@pytest.mark.parametrize("key,weight", [
    ("native_code_modified", 60), ("native_selinux_permissive", 20), ("native_kotlin_mismatch", 40),
])
def test_native_only_factors(key, weight):
    assert result({key: True, key + "_status": "DETECTED"}).factors == ((key, weight),)

@pytest.mark.parametrize("key", sorted(NATIVE_BOOL_SIGNALS))
def test_unavailable_does_not_mean_detection(key):
    assert result({key: False, key + "_status": "UNAVAILABLE"}).score == 0
    with pytest.raises(SignalsError):
        result({key: True, key + "_status": "UNAVAILABLE"})
    with pytest.raises(SignalsError):
        result({key: True})
    with pytest.raises(SignalsError):
        result({key: False, key + "_status": "DETECTED"})
    with pytest.raises(SignalsError):
        result({key: True, key + "_status": "yes"})

def test_native_metadata_survives_parser():
    r = parse_client_signals({"v": 1, "native_collector_version": "1",
                             "native_hook_frida_comparison": "MATCH",
                             "kotlin_hook_frida_comparison_status": "NOT_DETECTED"})
    assert len(r) == 3
    with pytest.raises(SignalsError):
        parse_client_signals({"v": 1, "native_hook_frida_comparison": "clean"})

def test_native_factors_cap_and_custom_policy():
    report = {"v": 1, "native_code_modified": True, "native_code_modified_status": "DETECTED",
              "native_kotlin_mismatch": True, "native_kotlin_mismatch_status": "DETECTED",
              "native_selinux_permissive": True, "native_selinux_permissive_status": "DETECTED"}
    assert result(report).score == 100
    policy = RiskPolicy.from_dict({"weights": {"native_kotlin_mismatch": 0}})
    r = assess(RiskInput(parse_client_signals(report)), policy, frozenset(), "login")
    assert r.score == 80

def test_native_signals_are_still_bound_to_signed_actions(policy):
    from test_actions import Env
    env = Env(policy)
    phone = env.phone()
    body = env.sign(phone, overrides={"signals": {"v": 1, "native_code_modified": True,
                                                "native_code_modified_status": "DETECTED"}})
    # A transit edit cannot strip native evidence without invalidating the signature.
    import base64, json
    data = json.loads(base64.b64decode(body["signedData"]))
    data["signals"]["native_code_modified"] = False
    from device_trust import reasons as R
    body["signedData"] = base64.b64encode(json.dumps(data).encode()).decode()
    decision = env.verify(body)
    assert decision["decision"] == "BLOCK"
    assert R.SIGNATURE_INVALID in decision["reasons"]
