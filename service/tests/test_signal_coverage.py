"""Run 14: typed coverage states for the Kotlin checks.

A denied or failed read must stay distinguishable from a completed clean
check, old clients must keep working, and coverage must never change scores.
"""

from datetime import datetime, timezone

import pytest

from device_trust.risk import RiskInput, RiskPolicy, assess
from device_trust.signals import (
    BOOL_SIGNALS,
    COUNTED_SIGNALS,
    LEGACY_BOOL_SIGNALS,
    NATIVE_BOOL_SIGNALS,
    VALUE_SIGNALS,
    SignalsError,
    coverage_summary,
    parse_client_signals,
)

NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)
DIGEST = "ab" * 32
EVIDENCE = {"os_patch_level": 202609, "attestation_security_level": "STRONG_BOX", "os_version": 160000,
            "vendor_patch_level": 20260905, "boot_patch_level": 20260905, "chain_type": "RKP",
            "attested_ids": {"brand": "google", "model": "Pixel 9 Pro"}}

LEGACY = {"v": 1, **{k: False for k in BOOL_SIGNALS}, "app_installer": "com.android.vending",
          "app_signature_sha256": DIGEST, "env_a11y_third_party": 0, "env_remote_access_apps": [],
          "os_security_patch": "2026-09-05", "os_release": "16",
          **{k + "_status": "NOT_DETECTED" for k in NATIVE_BOOL_SIGNALS}}


def with_states(base: dict, check_state: str = "NOT_DETECTED", reason: str = "COMPLETED") -> dict:
    """Shape produced by the Run 14 Kotlin collector."""
    out = {**base, "signal_coverage_version": 1}
    for key in LEGACY_BOOL_SIGNALS | COUNTED_SIGNALS:
        out[key + "_status"] = check_state
        out[key + "_reason"] = reason
    for key in VALUE_SIGNALS:
        out[key + "_status"] = "COLLECTED"
        out[key + "_reason"] = "COMPLETED"
    return out


CLEAN = with_states(LEGACY)
UNAVAILABLE = with_states(LEGACY, "UNAVAILABLE", "ACCESS_DENIED")


def score(signals: dict):
    r = assess(RiskInput(parse_client_signals(signals), None, EVIDENCE), RiskPolicy(), frozenset({DIGEST}), "login", NOW)
    return r.score, r.factors


def test_pre_run14_report_still_parses():
    out = parse_client_signals(LEGACY)
    assert "root_su_status" not in out
    assert coverage_summary(out)["UNREPORTED"] == len(LEGACY_BOOL_SIGNALS | COUNTED_SIGNALS)


def test_typed_report_keeps_states():
    out = parse_client_signals(UNAVAILABLE)
    assert out["root_su_status"] == "UNAVAILABLE" and out["root_su_reason"] == "ACCESS_DENIED"
    assert out["app_installer_status"] == "COLLECTED"
    assert out["signal_coverage_version"] == 1
    counts = coverage_summary(out)
    assert counts["UNAVAILABLE"] == len(LEGACY_BOOL_SIGNALS | COUNTED_SIGNALS)
    assert counts["NOT_DETECTED"] == 0


def test_coverage_never_changes_the_score():
    assert score(CLEAN) == score(LEGACY) == score(UNAVAILABLE)
    hit = {**UNAVAILABLE, "hook_frida": True, "hook_frida_status": "DETECTED", "hook_frida_reason": "COMPLETED"}
    assert score(hit) == score({**LEGACY, "hook_frida": True})


@pytest.mark.parametrize("bad", [
    {"v": 2},
    {"signal_coverage_version": 2},
    {"signal_coverage_version": "1"},
    {"root_su_status": "CLEAN"},
    {"root_su_status": "COLLECTED"},
    {"root_su_reason": "WHATEVER"},
    {"app_installer_status": "NOT_DETECTED"},
    {"root_su_status": 1},
])
def test_unknown_versions_and_vocabulary_are_rejected(bad):
    with pytest.raises(SignalsError):
        parse_client_signals({**CLEAN, **bad})


@pytest.mark.parametrize("bad", [
    # a detection must say DETECTED, and only a detection may
    {"root_su": True, "root_su_status": "UNAVAILABLE", "root_su_reason": "ACCESS_DENIED"},
    {"root_su": False, "root_su_status": "DETECTED"},
    # "completed" reasons only on completed states
    {"root_su_status": "UNAVAILABLE", "root_su_reason": "COMPLETED"},
    {"root_su_status": "NOT_DETECTED", "root_su_reason": "ACCESS_DENIED"},
    # counted signals
    {"env_a11y_third_party": 2, "env_a11y_third_party_status": "NOT_DETECTED"},
    {"env_remote_access_apps": ["anydesk"], "env_remote_access_apps_status": "UNAVAILABLE",
     "env_remote_access_apps_reason": "API_ERROR"},
    # an unavailable value must not carry a value
    {"app_installer_status": "UNAVAILABLE", "app_installer_reason": "API_ERROR"},
])
def test_contradictory_states_are_rejected(bad):
    with pytest.raises(SignalsError):
        parse_client_signals({**CLEAN, **bad})


def test_reason_requires_status_and_status_requires_value():
    no_status = dict(CLEAN)
    del no_status["root_su_status"]
    with pytest.raises(SignalsError):
        parse_client_signals(no_status)
    no_value = dict(CLEAN)
    del no_value["root_su"]
    with pytest.raises(SignalsError):
        parse_client_signals(no_value)


def test_no_installer_is_a_collected_fact():
    out = parse_client_signals({**CLEAN, "app_installer": None})
    assert out["app_installer"] is None and out["app_installer_status"] == "COLLECTED"
    failed = parse_client_signals({**CLEAN, "app_installer": None, "app_installer_status": "UNAVAILABLE",
                                   "app_installer_reason": "API_ERROR"})
    assert failed["app_installer_status"] == "UNAVAILABLE"


def test_partial_and_unsupported_states_parse():
    out = parse_client_signals({**CLEAN, "root_su_status": "UNAVAILABLE", "root_su_reason": "PARTIAL_COVERAGE",
                                "env_external_display_status": "UNSUPPORTED",
                                "env_external_display_reason": "API_UNSUPPORTED"})
    assert coverage_summary(out)["UNSUPPORTED"] == 1
