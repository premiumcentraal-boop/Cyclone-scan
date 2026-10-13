"""Generate risk_vectors.json from the server's risk engine.

The on-device engine in the scanner app (android/scanner .../risk/LocalRisk.kt)
must reproduce these results exactly; both test suites load this file.
Regenerate after changing weights or factor logic:

    python testvectors/generate_risk_vectors.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "service"))

from device_trust.risk import RiskInput, RiskPolicy, assess  # noqa: E402
from device_trust.signals import BOOL_SIGNALS, parse_client_signals  # noqa: E402

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)
DIGEST = "ab" * 32
CLEAN = {"v": 1, **{k: False for k in sorted(BOOL_SIGNALS)}, "app_installer": "com.android.vending",
         "app_signature_sha256": DIGEST, "env_a11y_third_party": 0, "env_remote_access_apps": [],
         "os_security_patch": "2026-09-05", "os_release": "16"}
_OS16 = {"os_version": 160000, "vendor_patch_level": 20260905, "boot_patch_level": 20260905}
TEE_FRESH = {"os_patch_level": 202609, "attestation_security_level": "TRUSTED_ENVIRONMENT", **_OS16,
             "chain_type": "RKP", "attested_ids": {"brand": "google", "model": "Pixel 9"}}
SB_FRESH = {"os_patch_level": 202609, "attestation_security_level": "STRONG_BOX", **_OS16,
            "chain_type": "RKP", "attested_ids": {"brand": "google", "model": "Pixel 9 Pro"}}
SAMSUNG_13 = {"os_patch_level": 202609, "attestation_security_level": "TRUSTED_ENVIRONMENT", "os_version": 130000,
              "vendor_patch_level": 20260901, "boot_patch_level": 20260901, "chain_type": "FACTORY",
              "attested_ids": {"brand": "samsung", "model": "SM-A546B"}}


def cases():
    """(name, client signals, attestation evidence[, reported Build ids])."""
    yield "clean_strongbox", CLEAN, SB_FRESH
    yield "clean_tee", CLEAN, TEE_FRESH
    for key in sorted(BOOL_SIGNALS):
        yield f"only_{key}", {**CLEAN, key: True}, SB_FRESH
    yield "sideloaded", {**CLEAN, "app_installer": None}, SB_FRESH
    yield "other_store", {**CLEAN, "app_installer": "com.other.store"}, SB_FRESH
    yield "resigned_app", {**CLEAN, "app_signature_sha256": "cd" * 32}, SB_FRESH
    yield "signature_unknown", {**CLEAN, "app_signature_sha256": None}, SB_FRESH
    yield "a11y_third_party", {**CLEAN, "env_a11y_third_party": 3}, SB_FRESH
    yield "remote_access_app", {**CLEAN, "env_remote_access_apps": ["anydesk", "rustdesk"]}, SB_FRESH
    yield "stale_patch", CLEAN, {"os_patch_level": 202401, "attestation_security_level": "TRUSTED_ENVIRONMENT"}
    yield "scam_call", {**CLEAN, "env_in_call": True, "env_remote_access_a11y": True,
                        "env_remote_access_apps": ["anydesk"], "env_a11y_third_party": 1}, TEE_FRESH
    yield "rooted_hooked", {**CLEAN, "root_magisk": True, "hook_zygisk": True, "hook_frida": True}, TEE_FRESH
    yield "emulator", {**CLEAN, "emu_build": True, "emu_files": True, "app_installer": None}, \
        {"os_patch_level": 202401, "attestation_security_level": "SOFTWARE"}
    yield "dev_phone", {**CLEAN, "env_dev_options": True, "env_adb": True, "env_vpn": True}, TEE_FRESH
    # Run 6: attestation provenance and consistency
    yield "factory_samsung_android13", {**CLEAN, "os_release": "13"}, SAMSUNG_13
    yield "factory_samsung_android14", {**CLEAN, "os_release": "14"}, {**SAMSUNG_13, "os_version": 140000}
    yield "leaked_keybox_on_pixel", CLEAN, {**SB_FRESH, "chain_type": "FACTORY"}
    yield "leaked_keybox_pixel_unattested_ids", CLEAN, {**SB_FRESH, "chain_type": "FACTORY", "attested_ids": {}}, \
        {"brand": "google", "model": "Pixel 8"}
    yield "unattested_ids_other_brand", {**CLEAN, "os_release": "13"}, {**SAMSUNG_13, "attested_ids": {}}, \
        {"brand": "Xiaomi", "model": "23127PN0CG"}
    yield "patch_props_spoofed", {**CLEAN, "os_security_patch": "2026-10-05"}, TEE_FRESH
    yield "patch_props_garbage", {**CLEAN, "os_security_patch": "n/a"}, TEE_FRESH
    yield "os_release_spoofed", {**CLEAN, "os_release": "14"}, TEE_FRESH
    yield "os_release_codename", {**CLEAN, "os_release": "Baklava"}, TEE_FRESH
    yield "vendor_patch_far_behind", CLEAN, {**TEE_FRESH, "vendor_patch_level": 20230105}
    yield "vendor_patch_lag_ok", CLEAN, {**TEE_FRESH, "vendor_patch_level": 20251105}
    yield "trickystore_full", {**CLEAN, "os_security_patch": "2026-10-05", "root_magisk": True}, \
        {**SB_FRESH, "chain_type": "FACTORY"}


def build() -> dict:
    policy = RiskPolicy()
    out = []
    for name, signals, evidence, *rest in cases():
        reported = rest[0] if rest else None
        result = assess(RiskInput(parse_client_signals(signals), None, evidence, reported_ids=reported), policy,
                        frozenset({DIGEST}), "login", NOW)
        out.append({
            "name": name,
            "signals": signals,
            "evidence": evidence,
            "reported": reported,
            "expected": {"score": result.score, "band": result.band, "factors": [list(f) for f in result.factors]},
        })
    return {
        "_comment": "Generated by generate_risk_vectors.py from the server risk engine. Do not edit by hand.",
        "now": NOW.isoformat(),
        "trusted_digests": [DIGEST],
        "rkp_required_models": sorted(policy.rkp_required_models),
        "thresholds": {"allow_below": policy.default_thresholds.allow_below,
                       "block_at": policy.default_thresholds.block_at},
        "cases": out,
    }


def render() -> str:
    return json.dumps(build(), indent=1, sort_keys=True) + "\n"


if __name__ == "__main__":
    (ROOT / "risk_vectors.json").write_text(render(), encoding="utf-8")
    print(f"wrote {len(build()['cases'])} cases")
