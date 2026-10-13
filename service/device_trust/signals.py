"""Client-reported device signals (RASP), Phase 3.

These come from code running on the phone, so a determined attacker can
hide or forge them: they raise risk, they never prove a device is clean.
Hardware attestation and Play Integrity remain the hard gates.

Wire format (flat, versioned):

    {"v": 1, "root_su": false, "hook_frida": true, ..., "app_installer": "com.android.vending",
     "env_a11y_third_party": 0, "env_remote_access_apps": ["anydesk"]}

Unknown keys are ignored (forward compatibility); known keys with the wrong
type make the whole report invalid.
"""

from __future__ import annotations

import re

SIGNALS_VERSION = 1

BOOL_SIGNALS = frozenset({
    # root
    "root_su", "root_magisk", "root_apps", "root_test_keys", "root_system_rw",
    # hooking / instrumentation
    "hook_frida", "hook_frida_port", "hook_xposed", "hook_zygisk",
    # debugging
    "debug_attached", "debug_traced", "debug_app_debuggable",
    # emulator
    "emu_build", "emu_files",
    # environment (social-engineering / remote-control indicators)
    "env_dev_options", "env_adb", "env_vpn", "env_in_call", "env_external_display",
    "env_remote_access_a11y",
})
INT_SIGNALS = frozenset({"env_a11y_third_party"})
STR_SIGNALS = frozenset({
    "app_installer", "app_signature_sha256",
    # Reported OS facts, cross-checked against the hardware attestation (Run 6):
    # Build.VERSION.SECURITY_PATCH ("2026-09-05") and Build.VERSION.RELEASE ("16").
    "os_security_patch", "os_release",
})
LIST_SIGNALS = frozenset({"env_remote_access_apps"})

MAX_STR = 128
MAX_LIST = 32
_TOKEN = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


class SignalsError(ValueError):
    pass


def parse_client_signals(raw: object) -> dict:
    """Validate and normalise a client signal report. Raises SignalsError."""
    if not isinstance(raw, dict):
        raise SignalsError("signals must be an object")
    if type(raw.get("v")) is not int or raw["v"] != SIGNALS_VERSION:
        raise SignalsError("unsupported signals version")
    out: dict = {}
    for key, value in raw.items():
        if key in BOOL_SIGNALS:
            if type(value) is not bool:
                raise SignalsError(f"{key} must be a boolean")
            out[key] = value
        elif key in INT_SIGNALS:
            if type(value) is not int or not 0 <= value <= 1000:
                raise SignalsError(f"{key} must be a small non-negative integer")
            out[key] = value
        elif key in STR_SIGNALS:
            if value is None:
                out[key] = None
            elif not isinstance(value, str) or len(value) > MAX_STR:
                raise SignalsError(f"{key} must be a short string or null")
            else:
                out[key] = value
        elif key in LIST_SIGNALS:
            if (
                not isinstance(value, list)
                or len(value) > MAX_LIST
                or not all(isinstance(v, str) and _TOKEN.match(v) for v in value)
            ):
                raise SignalsError(f"{key} must be a short list of identifiers")
            out[key] = sorted(set(value))
    return out
