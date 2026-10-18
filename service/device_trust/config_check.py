"""Pre-deployment configuration check (Run 18): ``device-trust check-config``.

Reads only local files. It makes no network calls, never prints secret values and does
not open (or migrate) the registry. ``beta`` applies the recommended beta settings of Runs
16-17; ``dev`` reports the same facts but only fails on configuration that cannot work.
A passing check is configuration hygiene, not a security review or release approval.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from .policy import TrustPolicy

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
BETA_FLAGS = ("require_principal", "require_bound_enrollment", "require_bound_device")
_PLACEHOLDER_DIGEST = "0" * 64
# The committed PUBLIC development signing certificate (android/signing/dev-signer.sha256).
DEV_SIGNER_SHA256 = "412b9e05c1418d4e5e1e0f86ee21687569b4623231f951e5cf6a8e67cc469416"
MIN_TOKEN_CHARS = 32


def _secret_file(path: str | None, name: str, out: list, required: bool) -> str | None:
    if not path:
        out.append({"check": name, "status": FAIL if required else WARN,
                    "detail": "not configured" + ("" if required else " (endpoints disabled)")})
        return None
    try:
        p = Path(path)
        value = p.read_text(encoding="utf-8").strip()
        mode = p.stat().st_mode
    except OSError as exc:
        out.append({"check": name, "status": FAIL, "detail": f"unreadable: {exc.strerror}"})
        return None
    if len(value) < MIN_TOKEN_CHARS:
        out.append({"check": name, "status": FAIL, "detail": f"shorter than {MIN_TOKEN_CHARS} characters"})
        return value
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        out.append({"check": name, "status": WARN, "detail": "file is readable by group/others; use mode 0600"})
    else:
        out.append({"check": name, "status": PASS, "detail": "present"})
    return value


def check(policy_path: str, *, profile: str = "beta", gateway_token_file: str | None = None,
          admin_token_file: str | None = None, play_service_account: str | None = None) -> dict:
    if profile not in ("beta", "dev"):
        raise ValueError("profile must be 'beta' or 'dev'")
    beta = profile == "beta"
    out: list[dict] = []
    try:
        policy = TrustPolicy.from_file(policy_path)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        out.append({"check": "policy", "status": FAIL, "detail": f"invalid policy: {exc}"})
        return _result(profile, None, out)
    out.append({"check": "policy", "status": PASS, "detail": "parses and validates"})

    for flag in BETA_FLAGS:
        on = getattr(policy, flag)
        out.append({"check": flag, "status": PASS if on else (FAIL if beta else WARN),
                    "detail": "enabled" if on else "disabled (recommended true for beta)"})
    if DEV_SIGNER_SHA256 in policy.signing_cert_sha256:
        out.append({"check": "dev_signing_key", "status": FAIL if beta else WARN,
                    "detail": "policy trusts the PUBLIC development key: anyone can sign an app with it"})
    if _PLACEHOLDER_DIGEST in policy.signing_cert_sha256:
        out.append({"check": "signing_cert_sha256", "status": FAIL,
                    "detail": "placeholder digest: set your app's signing certificate SHA-256"})
    else:
        out.append({"check": "signing_cert_sha256", "status": PASS,
                    "detail": f"{len(policy.signing_cert_sha256)} allowed signer(s); confirm with tools/release/check_signing.py"})
    if policy.package_name.startswith("com.example."):
        out.append({"check": "package_name", "status": WARN, "detail": "example package name"})
    out.append({"check": "fleet_hash_key", "status": PASS if policy.fleet_hash_key else WARN,
                "detail": "set" if policy.fleet_hash_key else "unset: network history resets on every restart"})
    out.append({"check": "policy_version", "status": PASS if policy.policy_version else WARN,
                "detail": policy.policy_version or "unset: scan results carry only the policy digest"})

    gateway = _secret_file(gateway_token_file, "gateway_token", out, required=beta or policy.require_principal)
    admin = _secret_file(admin_token_file, "admin_token", out, required=False)
    if gateway and admin and gateway == admin:
        out.append({"check": "token_separation", "status": FAIL, "detail": "gateway and admin tokens are identical"})

    play_needed = policy.require_play_integrity or policy.scan_require_play_integrity or bool(
        policy.play_integrity_required_actions)
    if play_service_account:
        try:
            raw = json.loads(Path(play_service_account).read_text(encoding="utf-8"))
            missing = [k for k in ("client_email", "private_key", "token_uri") if not raw.get(k)]
            ok = isinstance(raw, dict) and raw.get("type") == "service_account" and not missing
            out.append({"check": "play_service_account", "status": PASS if ok else FAIL,
                        "detail": "service-account key present (not contacted)" if ok
                        else f"not a usable service-account key (missing {missing or ['type']})"})
        except (OSError, ValueError, AttributeError) as exc:
            out.append({"check": "play_service_account", "status": FAIL, "detail": f"unreadable: {exc}"})
    else:
        out.append({"check": "play_service_account", "status": FAIL if play_needed else WARN,
                    "detail": "not configured: Play Integrity verdicts will be UNAVAILABLE"})
    return _result(profile, policy, out)


def _result(profile, policy, checks) -> dict:
    failed = [c["check"] for c in checks if c["status"] == FAIL]
    return {"profile": profile, "ok": not failed, "failed": failed,
            "policyDigest": policy.digest() if policy else None,
            "policyVersion": policy.policy_version if policy else None,
            "checks": checks,
            "note": "Local configuration hygiene only: not a security review, live Google check or release approval."}
