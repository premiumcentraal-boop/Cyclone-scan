"""Server-side trust policy. All values are operator-controlled configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path

from .key_description import SecurityLevel
from .risk import RiskPolicy


@dataclass(frozen=True)
class TrustPolicy:
    # App identity -----------------------------------------------------------
    package_name: str
    # SHA-256 digests (lowercase hex) of the app signing certificate(s) that are
    # allowed. Use the Play App Signing certificate for Play builds.
    signing_cert_sha256: frozenset[str]

    # Key attestation --------------------------------------------------------
    min_security_level: SecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT
    max_os_patch_age_months: int = 12
    # SHA-256 (lowercase hex) of verifiedBootKey values for custom OSes that are
    # allowed to report SELF_SIGNED with a locked bootloader (e.g. GrapheneOS).
    allowed_self_signed_boot_keys: frozenset[str] = frozenset()
    # Allowed clock skew when checking certificate validity windows.
    clock_skew_seconds: int = 300
    # Hard-require Google RKP-provisioned attestation keys (Run 6). Strongest
    # defence against leaked factory keyboxes, but rejects older phones that
    # only have factory keys; the risk engine's model list is the softer default.
    require_rkp: bool = False
    # Secret for hashing client network blocks (Run 12). Set it so fleet
    # history survives restarts; without it a random per-process key is used.
    fleet_hash_key: str = ""

    # Challenge / Play Integrity --------------------------------------------
    challenge_ttl_seconds: int = 120
    require_play_integrity: bool = False
    play_integrity_max_age_seconds: int = 300
    require_play_recognized: bool = True

    # Signed actions (Phase 2) ------------------------------------------------
    action_challenge_ttl_seconds: int = 120
    # Signed actions older than this (by their own timestamp) are rejected.
    action_max_age_seconds: int = 120
    # If non-empty, only these action types may be signed.
    allowed_action_types: frozenset[str] = frozenset()
    # Action types that must be signed with the biometric-bound confirm key.
    # Devices without a confirm key get STEP_UP for these.
    confirm_key_required_actions: frozenset[str] = frozenset()
    # Action types that must carry a fresh Play Integrity verdict.
    play_integrity_required_actions: frozenset[str] = frozenset()
    # Allow the confirm key to be unlocked with PIN/pattern as well as biometrics.
    confirm_key_allow_device_credential: bool = False

    # Risk scoring (Phase 3) -------------------------------------------------
    risk: RiskPolicy = field(default_factory=RiskPolicy)

    @classmethod
    def from_file(cls, path: str | Path) -> "TrustPolicy":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict) -> "TrustPolicy":
        known = {f.name for f in fields(cls)}
        unknown = set(raw) - known
        if unknown:
            raise ValueError(f"unknown policy keys: {sorted(unknown)}")
        values = dict(raw)
        values["signing_cert_sha256"] = frozenset(
            _normalize_hex(v) for v in raw.get("signing_cert_sha256", ())
        )
        values["allowed_self_signed_boot_keys"] = frozenset(
            _normalize_hex(v) for v in raw.get("allowed_self_signed_boot_keys", ())
        )
        for key in ("allowed_action_types", "confirm_key_required_actions", "play_integrity_required_actions"):
            if key in raw:
                values[key] = frozenset(str(v) for v in raw[key])
        if "risk" in raw:
            values["risk"] = RiskPolicy.from_dict(raw["risk"])
        if "min_security_level" in raw:
            values["min_security_level"] = SecurityLevel[str(raw["min_security_level"]).upper()]
        policy = cls(**values)
        policy.validate()
        return policy

    def validate(self) -> None:
        if not self.package_name:
            raise ValueError("package_name is required")
        if not self.signing_cert_sha256:
            raise ValueError("at least one signing_cert_sha256 is required")
        for digest in self.signing_cert_sha256 | self.allowed_self_signed_boot_keys:
            if len(digest) != 64:
                raise ValueError(f"expected 32-byte hex digest, got {digest!r}")
        if self.min_security_level < SecurityLevel.TRUSTED_ENVIRONMENT:
            raise ValueError("software-level attestation is never acceptable")
        if self.allowed_action_types:
            extra = (self.confirm_key_required_actions | self.play_integrity_required_actions) - self.allowed_action_types
            if extra:
                raise ValueError(f"action types not in allowed_action_types: {sorted(extra)}")


def _normalize_hex(value: str) -> str:
    cleaned = value.replace(":", "").strip().lower()
    int(cleaned, 16)  # raises ValueError for non-hex input
    return cleaned
