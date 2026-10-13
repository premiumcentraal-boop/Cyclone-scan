"""Trust decisions.

* Enrollment (Phase 1): hard-fail gates, ALLOW / BLOCK.
* Signed actions (Phase 2): the enrolled hardware key signs each sensitive
  action; ALLOW / STEP_UP / BLOCK.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime

from . import reasons as R
from .actions import (
    KEY_CONFIRM,
    KEY_DEVICE,
    SignedDataError,
    action_request_hash,
    parse_signed_data,
    verify_signature,
)
from .attestation import AttestationEvidence, AttestationResult, AttestationVerifier
from .challenges import Challenge, ChallengeStore
from .key_description import AUTH_BIOMETRIC, AUTH_PASSWORD
from .play_integrity import DecodeError, IntegrityTokenDecoder, b64url, enrollment_request_hash, evaluate_payload
from .policy import TrustPolicy
from .registry import DeviceRegistry, DuplicateDeviceKey

log = logging.getLogger("device_trust.decisions")

ALLOW = "ALLOW"
STEP_UP = "STEP_UP"
BLOCK = "BLOCK"

# Reasons that ask for stronger authentication instead of blocking outright.
_STEP_UP_REASONS = frozenset({R.CONFIRM_KEY_REQUIRED})


@dataclass(frozen=True)
class EnrollmentRequest:
    challenge_id: str
    attestation_chain: list[bytes]
    reported_ids: dict[str, str]
    play_integrity_token: str | None = None
    # Optional second key that can only sign after strong biometric auth.
    confirm_key_chain: list[bytes] | None = None


@dataclass(frozen=True)
class EnrollmentDecision:
    decision: str
    decision_id: str
    reasons: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    device_id: str | None = None
    evidence: AttestationEvidence | None = None
    play_signals: dict | None = field(default=None)
    has_confirm_key: bool = False


@dataclass(frozen=True)
class ActionRequest:
    device_id: str
    challenge_id: str
    signed_data: bytes
    signature: bytes
    key: str = KEY_DEVICE
    play_integrity_token: str | None = None


@dataclass(frozen=True)
class ActionDecision:
    decision: str
    decision_id: str
    reasons: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    # Only on ALLOW: exactly what the device signed, for the backend to execute.
    action_type: str | None = None
    params: dict | None = None


def confirm_key_auth_ok(evidence: AttestationEvidence, allow_device_credential: bool = False) -> bool:
    """True if the hardware only lets this key sign after a fresh strong-biometric auth."""
    allowed = AUTH_BIOMETRIC | (AUTH_PASSWORD if allow_device_credential else 0)
    auth = evidence.user_auth_type or 0
    return (
        not evidence.no_auth_required
        and bool(auth & AUTH_BIOMETRIC)
        and not auth & ~allowed
        and evidence.auth_timeout in (None, 0)  # authenticate for every signature, no time window
    )


class DeviceTrustService:
    def __init__(
        self,
        policy: TrustPolicy,
        verifier: AttestationVerifier,
        challenges: ChallengeStore,
        registry: DeviceRegistry,
        play_decoder: IntegrityTokenDecoder | None = None,
    ):
        self.policy = policy
        self._verifier = verifier
        self._challenges = challenges
        self._registry = registry
        self._play = play_decoder

    def issue_challenge(self) -> Challenge:
        return self._challenges.issue()

    def issue_action_challenge(self, device_id: str) -> Challenge | None:
        """Challenge bound to one active device; None if unknown or revoked."""
        record = self._registry.get(device_id)
        if record is None or not record.active:
            return None
        return self._challenges.issue(bound_to=device_id, ttl_seconds=self.policy.action_challenge_ttl_seconds)

    def revoke_device(self, device_id: str, reason: str) -> bool:
        revoked = self._registry.revoke(device_id, reason)
        log.info(json.dumps({"event": "device_revoked", "device_id": device_id, "found": revoked, "reason": reason}))
        return revoked

    def enroll(self, req: EnrollmentRequest, now: datetime | None = None) -> EnrollmentDecision:
        decision_id = "dec_" + secrets.token_urlsafe(12)
        nonce = self._challenges.consume(req.challenge_id)
        if nonce is None:
            return self._finish(decision_id, [R.CHALLENGE_UNKNOWN], [], None, None, None)

        att = self._verifier.verify(req.attestation_chain, nonce, req.reported_ids, now=now)
        reasons = list(att.reasons)
        warnings: list[str] = []
        play_signals = None

        if att.leaf_public_key_spki is not None:
            play_signals = self._check_play(
                req.play_integrity_token,
                enrollment_request_hash(nonce, att.leaf_public_key_spki),
                self.policy.require_play_integrity,
                reasons,
                warnings,
                now,
            )

        confirm = None
        if req.confirm_key_chain:
            confirm = self._verifier.verify(req.confirm_key_chain, nonce, req.reported_ids, now=now)
            reasons.extend(self._confirm_key_reasons(att, confirm))

        device_id = None
        if not reasons:
            try:
                device_id = self._registry.register(
                    att.leaf_public_key_spki,
                    att.evidence,
                    play_signals,
                    confirm_key_spki=confirm.leaf_public_key_spki if confirm else None,
                    confirm_evidence=confirm.evidence if confirm else None,
                )
            except DuplicateDeviceKey:
                reasons.append(R.KEY_ALREADY_ENROLLED)
        return self._finish(decision_id, reasons, warnings, device_id, att.evidence, play_signals,
                            has_confirm_key=confirm is not None)

    def _confirm_key_reasons(self, device: AttestationResult, confirm: AttestationResult) -> list[str]:
        if not confirm.ok or confirm.evidence is None or device.evidence is None:
            return [R.CONFIRM_KEY_INVALID]
        out = []
        dev, con = device.evidence, confirm.evidence
        # Both keys must come from the same secure hardware, and be different keys.
        if (
            con.leaf_spki_sha256 == dev.leaf_spki_sha256
            or con.verified_boot_key_sha256 != dev.verified_boot_key_sha256
            or con.attested_ids != dev.attested_ids
        ):
            out.append(R.CONFIRM_KEY_INVALID)
        if not confirm_key_auth_ok(con, self.policy.confirm_key_allow_device_credential):
            out.append(R.CONFIRM_KEY_NOT_USER_AUTH_BOUND)
        return out

    def _check_play(self, token, expected_hash, required, reasons, warnings, now) -> dict | None:
        """Evaluate an optional Play Integrity token; appends to reasons/warnings in place."""
        if not token:
            if required:
                reasons.append(R.PLAY_INTEGRITY_MISSING)
            return None
        if self._play is None:
            (reasons if required else warnings).append(R.PLAY_INTEGRITY_UNAVAILABLE)
            return None
        try:
            payload = self._play.decode(self.policy.package_name, token)
        except DecodeError:
            (reasons if required else warnings).append(R.PLAY_INTEGRITY_UNAVAILABLE)
            return None
        now_ms = int(now.timestamp() * 1000) if now else None
        play = evaluate_payload(payload, self.policy, expected_hash, now_ms)
        reasons.extend(play.reasons)
        return play.signals

    # --- Phase 2: signed actions ---------------------------------------------

    def verify_action(self, req: ActionRequest, now: datetime | None = None) -> ActionDecision:
        decision_id = "dec_" + secrets.token_urlsafe(12)
        reasons: list[str] = []
        warnings: list[str] = []
        # Burn the challenge first so it can never be retried, whatever happens next.
        nonce = self._challenges.consume(req.challenge_id, bound_to=req.device_id)
        record = self._registry.get(req.device_id)
        if record is None:
            return self._finish_action(decision_id, req, [R.DEVICE_UNKNOWN], warnings, None)
        if not record.active:
            return self._finish_action(decision_id, req, [R.DEVICE_REVOKED], warnings, None)
        if nonce is None:
            return self._finish_action(decision_id, req, [R.CHALLENGE_UNKNOWN], warnings, None)

        try:
            action = parse_signed_data(req.signed_data)
        except SignedDataError:
            return self._finish_action(decision_id, req, [R.SIGNED_DATA_MALFORMED], warnings, None)

        if (
            action.device_id != req.device_id
            or action.challenge_id != req.challenge_id
            or action.nonce != b64url(nonce)
        ):
            reasons.append(R.SIGNED_DATA_MISMATCH)

        now_ms = int((now.timestamp() if now else time.time()) * 1000)
        skew_ms = self.policy.clock_skew_seconds * 1000
        if action.timestamp_ms > now_ms + skew_ms or now_ms - action.timestamp_ms > self.policy.action_max_age_seconds * 1000:
            reasons.append(R.ACTION_STALE)

        if req.key == KEY_CONFIRM:
            key_spki = record.confirm_key_spki
        elif req.key == KEY_DEVICE:
            key_spki = record.public_key_spki
        else:
            key_spki = None
        if key_spki is None or not verify_signature(key_spki, req.signed_data, req.signature):
            reasons.append(R.SIGNATURE_INVALID)

        p = self.policy
        if p.allowed_action_types and action.action_type not in p.allowed_action_types:
            reasons.append(R.ACTION_TYPE_NOT_ALLOWED)
        if action.action_type in p.confirm_key_required_actions and req.key != KEY_CONFIRM:
            reasons.append(R.CONFIRM_KEY_REQUIRED)

        self._check_play(
            req.play_integrity_token,
            action_request_hash(req.signed_data),
            action.action_type in p.play_integrity_required_actions,
            reasons,
            warnings,
            now,
        )
        return self._finish_action(decision_id, req, reasons, warnings, action)

    def _finish_action(self, decision_id, req, reasons, warnings, action) -> ActionDecision:
        reasons_t = tuple(dict.fromkeys(reasons))
        if not reasons_t:
            decision = ALLOW
            self._registry.touch(req.device_id)
        elif set(reasons_t) <= _STEP_UP_REASONS:
            decision = STEP_UP
        else:
            decision = BLOCK
        result = ActionDecision(
            decision=decision,
            decision_id=decision_id,
            reasons=reasons_t,
            warnings=tuple(dict.fromkeys(warnings)),
            action_type=action.action_type if action and decision == ALLOW else None,
            params=action.params if action and decision == ALLOW else None,
        )
        log.info(
            json.dumps(
                {
                    "event": "action",
                    "decision_id": decision_id,
                    "decision": decision,
                    "reasons": list(reasons_t),
                    "warnings": list(result.warnings),
                    "device_id": req.device_id,
                    "key": req.key,
                    # The type is logged; params may contain account data and are not.
                    "action_type": action.action_type if action else None,
                },
                sort_keys=True,
            )
        )
        return result

    def _finish(self, decision_id, reasons, warnings, device_id, evidence, play_signals,
                has_confirm_key=False) -> EnrollmentDecision:
        reasons_t = tuple(dict.fromkeys(reasons))
        decision = EnrollmentDecision(
            decision=ALLOW if not reasons_t else BLOCK,
            decision_id=decision_id,
            reasons=reasons_t,
            warnings=tuple(dict.fromkeys(warnings)),
            device_id=device_id,
            evidence=evidence,
            play_signals=play_signals,
            has_confirm_key=has_confirm_key and device_id is not None,
        )
        log.info(
            json.dumps(
                {
                    "event": "enrollment",
                    "decision_id": decision_id,
                    "decision": decision.decision,
                    "reasons": list(decision.reasons),
                    "warnings": list(decision.warnings),
                    "device_id": device_id,
                    "security_level": evidence.attestation_security_level if evidence else None,
                    "boot_state": evidence.verified_boot_state if evidence else None,
                    "os_patch_level": evidence.os_patch_level if evidence else None,
                    "brand": evidence.attested_ids.get("brand") if evidence else None,
                    "model": evidence.attested_ids.get("model") if evidence else None,
                    "play_device": play_signals.get("device_recognition") if play_signals else None,
                    "confirm_key": has_confirm_key,
                },
                sort_keys=True,
            )
        )
        return decision
