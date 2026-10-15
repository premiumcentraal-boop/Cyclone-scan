"""Server-side trust policy. All values are operator-controlled configuration."""

from __future__ import annotations

import enum
import hashlib
import json
import re
from dataclasses import dataclass, field, fields, is_dataclass
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
    # Run 15: follow Google's guidance that expired certificates in factory
    # chains under its RSA root stay trustworthy unless revoked. Only that exact
    # chain form is exempt; set False to enforce validity everywhere.
    legacy_factory_validity_exemption: bool = True
    # Secret for hashing client network blocks (Run 12). Set it so fleet
    # history survives restarts; without it a random per-process key is used.
    fleet_hash_key: str = ""

    # Challenge / Play Integrity --------------------------------------------
    challenge_ttl_seconds: int = 120
    require_bound_enrollment: bool = False
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

    # Device lifecycle (Run 16) ----------------------------------------------
    # Reject requests that do not carry an authenticated gateway principal
    # (tenant + account). Recommended for any customer deployment.
    require_principal: bool = False
    # State for an otherwise-ALLOW enrollment without Run 20 evidence binding
    # (legacy migration mode): "active" keeps the old behaviour, "pending"
    # holds it until an authenticated step-up completion.
    unbound_enrollment_state: str = "active"
    # Quarantine: refuse protected actions from devices whose enrollment was not
    # evidence-bound (LEGACY_UNBOUND or enrolled before Run 16), until they
    # enroll again with binding.
    require_bound_device: bool = False
    # A pending device that is not completed within this time is revoked on the
    # next completion attempt; the user enrolls again.
    pending_ttl_seconds: int = 7 * 24 * 3600

    # Server-verified scan, refresh and history (Run 17) ----------------------
    # Operator label returned with every scan result (e.g. "beta-2026-10"). The
    # result also carries policy_digest(), so the label need not be trusted.
    policy_version: str = ""
    scan_challenge_ttl_seconds: int = 120
    # Scan and key-rotation transcripts older than this (by their own ts) are rejected.
    scan_max_age_seconds: int = 120
    # Display/caching bound on a scan result ("freshUntil"); not a guarantee.
    scan_result_ttl_seconds: int = 300
    # Require a fresh attestation chain (ephemeral key, scan nonce) for a scan.
    scan_require_fresh_attestation: bool = True
    scan_require_play_integrity: bool = False
    # Scan-refresh snapshots kept per device; enrollment and rotation snapshots are kept.
    history_max_snapshots: int = 50
    # Run 28: what a scan does when its fresh attestation contradicts the enrolled device
    # (a REVIEW history finding: other attested model, boot key or lock state, or a patch
    # that went backwards). "step_up" returns STEP_UP with SCAN_DEVICE_EVIDENCE_CHANGED;
    # "report" only lists the finding (the Run 17 behaviour). Legitimate OS updates are
    # INFO findings and never trigger it.
    scan_history_review: str = "step_up"

    # Retention (Run 29) ---------------------------------------------------------
    # Rows older than these are deleted by the retention sweep (serve runs it every
    # retention_sweep_interval_seconds; `device-trust purge` runs it once). Each must
    # cover the risk window that reads the table. Device records, their enrollment and
    # key-rotation snapshots and retired-key tombstones are kept while the device
    # exists, because they enforce "a revoked or retired key never enrolls again".
    retention_decisions_days: int = 365        # audit trail and per-device velocity
    retention_fleet_events_days: int = 30      # network/cohort burst history
    retention_key_uses_days: int = 90          # leaked-keybox history
    retention_lifecycle_events_days: int = 730
    retention_scan_snapshots_days: int = 365   # scan-refresh snapshots only
    retention_sweep_interval_seconds: int = 3600

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

    def digest(self) -> str:
        """First 16 hex of SHA-256 over the canonical policy JSON, secrets excluded.

        Lets an operator match a scan result to the exact policy file that produced it.
        """
        data = _plain(self)
        data.pop("fleet_hash_key", None)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    def validate(self) -> None:
        for flag in ("require_bound_enrollment", "require_principal", "require_bound_device",
                     "scan_require_fresh_attestation", "scan_require_play_integrity"):
            if type(getattr(self, flag)) is not bool:
                raise ValueError(f"{flag} must be boolean")
        for key in ("scan_challenge_ttl_seconds", "scan_max_age_seconds", "scan_result_ttl_seconds",
                    "history_max_snapshots"):
            value = getattr(self, key)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{key} must be a positive integer")
        if not isinstance(self.policy_version, str) or not _VERSION_LABEL.match(self.policy_version):
            raise ValueError("policy_version must be at most 64 characters of [A-Za-z0-9._:-]")
        if self.scan_history_review not in ("step_up", "report"):
            raise ValueError("scan_history_review must be 'step_up' or 'report'")
        if self.unbound_enrollment_state not in ("active", "pending"):
            raise ValueError("unbound_enrollment_state must be 'active' or 'pending'")
        if type(self.pending_ttl_seconds) is not int or self.pending_ttl_seconds <= 0:
            raise ValueError("pending_ttl_seconds must be a positive integer")
        if not self.package_name:
            raise ValueError("package_name is required")
        if not self.signing_cert_sha256:
            raise ValueError("at least one signing_cert_sha256 is required")
        for digest in self.signing_cert_sha256 | self.allowed_self_signed_boot_keys:
            if len(digest) != 64:
                raise ValueError(f"expected 32-byte hex digest, got {digest!r}")
        if self.min_security_level < SecurityLevel.TRUSTED_ENVIRONMENT:
            raise ValueError("software-level attestation is never acceptable")
        self._validate_retention()
        if self.allowed_action_types:
            extra = (self.confirm_key_required_actions | self.play_integrity_required_actions) - self.allowed_action_types
            if extra:
                raise ValueError(f"action types not in allowed_action_types: {sorted(extra)}")


    RETENTION_KEYS = ("retention_decisions_days", "retention_fleet_events_days", "retention_key_uses_days",
                      "retention_lifecycle_events_days", "retention_scan_snapshots_days",
                      "retention_sweep_interval_seconds")

    def _validate_retention(self) -> None:
        for key in self.RETENTION_KEYS:
            value = getattr(self, key)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{key} must be a positive integer")
        day = 86400
        # A table must outlive the risk window that reads it, or pruning would silently
        # weaken a risk factor.
        needs = (
            ("retention_decisions_days", self.risk.velocity_window_seconds),
            ("retention_fleet_events_days", self.risk.fleet_window_seconds),
            ("retention_key_uses_days", self.risk.keybox_window_seconds),
        )
        for key, window in needs:
            if getattr(self, key) * day < window:
                raise ValueError(f"{key} is shorter than the risk window that reads it ({window} s)")

    def retention_cutoffs(self, now: float) -> dict[str, float]:
        """Epoch-second cutoffs: rows created before these are deleted."""
        day = 86400
        return {
            "decisions": now - self.retention_decisions_days * day,
            "fleet_events": now - self.retention_fleet_events_days * day,
            "attestation_key_uses": now - self.retention_key_uses_days * day,
            "lifecycle_events": now - self.retention_lifecycle_events_days * day,
            "scan_snapshots": now - self.retention_scan_snapshots_days * day,
        }


_VERSION_LABEL = re.compile(r"^[A-Za-z0-9._:-]{0,64}$")


def _plain(value):
    if isinstance(value, enum.Enum):
        return value.name
    if is_dataclass(value):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, (set, frozenset)):
        return sorted(_plain(v) for v in value)
    if isinstance(value, dict) or hasattr(value, "items"):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _normalize_hex(value: str) -> str:
    cleaned = value.replace(":", "").strip().lower()
    int(cleaned, 16)  # raises ValueError for non-hex input
    return cleaned
