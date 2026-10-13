"""Explainable risk scoring (Phase 3).

Hard gates (attestation, signatures, Play Integrity device verdict) still
decide BLOCK on their own. Risk scoring sits on top: every observed factor
adds points from an operator-tunable weight table, the total is capped at
100, and per-action thresholds map it to ALLOW / STEP_UP / BLOCK. The
factor list is kept with every decision so fraud teams can see *why*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Mapping

ALLOW = "ALLOW"
STEP_UP = "STEP_UP"
BLOCK = "BLOCK"

DEFAULT_WEIGHTS: Mapping[str, int] = MappingProxyType({
    # Client: root
    "root_su": 40,
    "root_magisk": 50,
    "root_apps": 25,
    "root_test_keys": 20,
    "root_system_rw": 40,
    # Client: hooking / instrumentation
    "hook_frida": 70,
    "hook_frida_port": 50,
    "hook_xposed": 60,
    "hook_zygisk": 50,
    # Client: debugging
    "debug_attached": 50,
    "debug_traced": 50,
    "debug_app_debuggable": 40,
    # Client: emulator
    "emu_build": 60,
    "emu_files": 60,
    # Client: app integrity
    "app_installer_untrusted": 30,
    "app_signature_mismatch": 80,
    # Client: environment / social engineering
    "env_dev_options": 5,
    "env_adb": 10,
    "env_vpn": 5,
    "env_in_call": 25,
    "env_external_display": 30,
    "env_a11y_third_party": 10,
    "env_remote_access_apps": 15,
    "env_remote_access_a11y": 45,
    "client_signals_missing": 20,
    # Play Integrity (fresh token only)
    "play_no_strong_integrity": 10,
    "play_capturing_apps": 25,
    "play_controlling_apps": 45,
    "play_overlay_apps": 15,
    "play_protect_possible_risk": 10,
    "play_protect_medium_risk": 25,
    "play_protect_high_risk": 50,
    "play_activity_level_3": 20,
    "play_activity_level_4": 40,
    "play_unlicensed": 30,
    # Hardware evidence / history
    "os_patch_stale": 10,
    "no_strongbox": 0,
    "device_new": 10,
    "velocity_high": 30,
})

_PLAY_PROTECT = {
    "POSSIBLE_RISK": "play_protect_possible_risk",
    "MEDIUM_RISK": "play_protect_medium_risk",
    "HIGH_RISK": "play_protect_high_risk",
}
_ACTIVITY = {"LEVEL_3": "play_activity_level_3", "LEVEL_4": "play_activity_level_4"}


@dataclass(frozen=True)
class Thresholds:
    """Scores below ``allow_below`` → ALLOW; at or above ``block_at`` → BLOCK; between → STEP_UP."""

    allow_below: int
    block_at: int

    def band(self, score: int) -> str:
        if score >= self.block_at:
            return BLOCK
        if score >= self.allow_below:
            return STEP_UP
        return ALLOW


@dataclass(frozen=True)
class RiskPolicy:
    weights: Mapping[str, int] = DEFAULT_WEIGHTS
    default_thresholds: Thresholds = Thresholds(allow_below=50, block_at=80)
    enrollment_thresholds: Thresholds = Thresholds(allow_below=60, block_at=90)
    action_thresholds: Mapping[str, Thresholds] = field(default_factory=dict)
    trusted_installers: frozenset[str] = frozenset({"com.android.vending"})
    stale_patch_months: int = 6
    new_device_seconds: int = 24 * 3600
    velocity_window_seconds: int = 3600
    velocity_max_actions: int = 30

    @classmethod
    def from_dict(cls, raw: dict) -> "RiskPolicy":
        known = {"weights", "default_thresholds", "enrollment_thresholds", "action_thresholds",
                 "trusted_installers", "stale_patch_months", "new_device_seconds",
                 "velocity_window_seconds", "velocity_max_actions"}
        unknown = set(raw) - known
        if unknown:
            raise ValueError(f"unknown risk policy keys: {sorted(unknown)}")
        values: dict = {}
        if "weights" in raw:
            extra = set(raw["weights"]) - set(DEFAULT_WEIGHTS)
            if extra:
                raise ValueError(f"unknown risk factors: {sorted(extra)}")
            merged = dict(DEFAULT_WEIGHTS)
            merged.update({k: int(v) for k, v in raw["weights"].items()})
            values["weights"] = MappingProxyType(merged)
        for key in ("default_thresholds", "enrollment_thresholds"):
            if key in raw:
                values[key] = Thresholds(**raw[key])
        if "action_thresholds" in raw:
            values["action_thresholds"] = {k: Thresholds(**v) for k, v in raw["action_thresholds"].items()}
        if "trusted_installers" in raw:
            values["trusted_installers"] = frozenset(raw["trusted_installers"])
        for key in ("stale_patch_months", "new_device_seconds", "velocity_window_seconds", "velocity_max_actions"):
            if key in raw:
                values[key] = int(raw[key])
        policy = cls(**values)
        policy.validate()
        return policy

    def validate(self) -> None:
        for name, t in [("default", self.default_thresholds), ("enrollment", self.enrollment_thresholds),
                        *self.action_thresholds.items()]:
            if not 0 < t.allow_below <= t.block_at <= 101:
                raise ValueError(f"invalid thresholds for {name}: need 0 < allow_below <= block_at <= 101")
        if any(w < 0 for w in self.weights.values()):
            raise ValueError("risk weights must be non-negative")

    def thresholds_for(self, action_type: str | None) -> Thresholds:
        if action_type is None:
            return self.enrollment_thresholds
        return self.action_thresholds.get(action_type, self.default_thresholds)


@dataclass(frozen=True)
class RiskInput:
    client_signals: dict | None
    play_signals: dict | None = None
    evidence: dict | None = None  # AttestationEvidence as a dict
    device_age_seconds: float | None = None
    recent_actions: int | None = None


@dataclass(frozen=True)
class RiskResult:
    score: int
    band: str
    factors: tuple[tuple[str, int], ...]  # (factor, points), highest first

    def factor_names(self) -> list[str]:
        return [name for name, _ in self.factors]


def _patch_age_months(level: int, now: datetime) -> int | None:
    if level > 999999:
        level //= 100
    year, month = divmod(level, 100)
    if not 1 <= month <= 12 or year < 2000:
        return None
    return (now.year - year) * 12 + (now.month - month)


def observed_factors(inp: RiskInput, policy: RiskPolicy, signing_digests: frozenset[str],
                     now: datetime) -> list[str]:
    found: list[str] = []
    c = inp.client_signals
    if c is None:
        found.append("client_signals_missing")
    else:
        found.extend(sorted(k for k, v in c.items() if v is True))
        if c.get("env_a11y_third_party", 0) > 0:
            found.append("env_a11y_third_party")
        if c.get("env_remote_access_apps"):
            found.append("env_remote_access_apps")
        if "app_installer" in c and c["app_installer"] not in policy.trusted_installers:
            found.append("app_installer_untrusted")
        digest = c.get("app_signature_sha256")
        if digest and digest.replace(":", "").lower() not in signing_digests:
            found.append("app_signature_mismatch")

    p = inp.play_signals
    if p:
        if "MEETS_STRONG_INTEGRITY" not in (p.get("device_recognition") or ()):
            found.append("play_no_strong_integrity")
        apps = p.get("app_access_risk") or ()
        if any(a.endswith("_CAPTURING") for a in apps):
            found.append("play_capturing_apps")
        if any(a.endswith("_CONTROLLING") for a in apps):
            found.append("play_controlling_apps")
        if any(a.endswith("_OVERLAYS") for a in apps):
            found.append("play_overlay_apps")
        if p.get("play_protect") in _PLAY_PROTECT:
            found.append(_PLAY_PROTECT[p["play_protect"]])
        if p.get("device_activity_level") in _ACTIVITY:
            found.append(_ACTIVITY[p["device_activity_level"]])
        if p.get("app_licensing") == "UNLICENSED":
            found.append("play_unlicensed")

    e = inp.evidence
    if e:
        level = e.get("os_patch_level")
        age = _patch_age_months(level, now) if isinstance(level, int) else None
        if age is not None and age > policy.stale_patch_months:
            found.append("os_patch_stale")
        if e.get("attestation_security_level") != "STRONG_BOX":
            found.append("no_strongbox")

    if inp.device_age_seconds is not None and inp.device_age_seconds < policy.new_device_seconds:
        found.append("device_new")
    if inp.recent_actions is not None and inp.recent_actions >= policy.velocity_max_actions:
        found.append("velocity_high")
    return list(dict.fromkeys(found))


def assess(inp: RiskInput, policy: RiskPolicy, signing_digests: frozenset[str],
           action_type: str | None = None, now: datetime | None = None) -> RiskResult:
    """Score a request. ``action_type=None`` means enrollment."""
    now = now or datetime.now(timezone.utc)
    factors = [(f, policy.weights.get(f, 0)) for f in observed_factors(inp, policy, signing_digests, now)]
    factors.sort(key=lambda fp: (-fp[1], fp[0]))
    score = min(100, sum(points for _, points in factors))
    return RiskResult(score, policy.thresholds_for(action_type).band(score), tuple(factors))
