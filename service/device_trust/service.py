"""Trust decisions.

* Enrollment (Phase 1): hard-fail gates, ALLOW / BLOCK.
* Signed actions (Phase 2): the enrolled hardware key signs each sensitive
  action; ALLOW / STEP_UP / BLOCK.
* Risk scoring (Phase 3): client signals, fresh Play Integrity signals,
  hardware evidence and history add up to an explainable score that can
  turn an otherwise-clean request into STEP_UP or BLOCK. Hard gates always win.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import asdict, dataclass, field
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
from .fleet import NetworkHasher, cohort_key
from .risk import RiskInput, RiskResult, assess, device_model_key
from .risk import BLOCK as RISK_BAND_BLOCK
from .risk import STEP_UP as RISK_BAND_STEP_UP
from .signals import SignalsError, parse_client_signals

log = logging.getLogger("device_trust.decisions")

ALLOW = "ALLOW"
STEP_UP = "STEP_UP"
BLOCK = "BLOCK"

# Reasons that ask for stronger authentication instead of blocking outright.
_STEP_UP_REASONS = frozenset({R.CONFIRM_KEY_REQUIRED, R.RISK_STEP_UP})


@dataclass(frozen=True)
class EnrollmentRequest:
    challenge_id: str
    attestation_chain: list[bytes]
    reported_ids: dict[str, str]
    play_integrity_token: str | None = None
    # Optional second key that can only sign after strong biometric auth.
    confirm_key_chain: list[bytes] | None = None
    # Optional client signal report (see signals.py); validated here.
    client_signals: object = None
    # Caller's IP as seen by the API; only a keyed hash of its network block is kept.
    client_ip: str | None = None


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
    risk: RiskResult | None = None


@dataclass(frozen=True)
class ActionRequest:
    device_id: str
    challenge_id: str
    signed_data: bytes
    signature: bytes
    key: str = KEY_DEVICE
    play_integrity_token: str | None = None
    client_ip: str | None = None


@dataclass(frozen=True)
class ActionDecision:
    decision: str
    decision_id: str
    reasons: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    # Only on ALLOW: exactly what the device signed, for the backend to execute.
    action_type: str | None = None
    params: dict | None = None
    risk: RiskResult | None = None


def decide(reasons) -> str:
    """BLOCK on any hard reason; STEP_UP if only step-up reasons; else ALLOW."""
    if not reasons:
        return ALLOW
    return STEP_UP if set(reasons) <= _STEP_UP_REASONS else BLOCK


def _risk_reason(risk: RiskResult) -> str | None:
    return {RISK_BAND_BLOCK: R.RISK_BLOCK, RISK_BAND_STEP_UP: R.RISK_STEP_UP}.get(risk.band)


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
        self._networks = NetworkHasher(policy.fleet_hash_key)

    def issue_challenge(self) -> Challenge:
        return self._challenges.issue()

    def issue_action_challenge(self, device_id: str) -> Challenge | None:
        """Challenge bound to one active device; None if unknown or revoked."""
        record = self._registry.get(device_id)
        if record is None or not record.active:
            return None
        return self._challenges.issue(bound_to=device_id, ttl_seconds=self.policy.action_challenge_ttl_seconds)

    def device_detail(self, device_id: str, limit: int = 50) -> dict | None:
        record = self._registry.get(device_id)
        if record is None:
            return None
        ev = record.evidence
        return {
            "deviceId": record.device_id,
            "status": record.status,
            "enrolledAt": record.enrolled_at,
            "hasConfirmKey": record.confirm_key_spki is not None,
            "attested": {
                "securityLevel": ev.get("attestation_security_level"),
                "bootState": ev.get("verified_boot_state"),
                "osPatchLevel": ev.get("os_patch_level"),
                "brand": (ev.get("attested_ids") or {}).get("brand"),
                "model": (ev.get("attested_ids") or {}).get("model"),
            },
            "decisions": [
                {
                    "decisionId": d["decision_id"],
                    "kind": d["kind"],
                    "actionType": d["action_type"],
                    "decision": d["decision"],
                    "riskScore": d["risk_score"],
                    "factors": [{"factor": f, "points": p} for f, p in d["factors"]],
                    "reasons": d["reasons"],
                    "at": d["created_at"],
                }
                for d in self._registry.decisions_for(device_id, limit)
            ],
        }

    def fleet_summary(self, window_seconds: float | None = None, limit: int = 10) -> dict:
        return self._registry.fleet_summary(window_seconds or 24 * 3600, limit)

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

        client_signals = None
        if req.client_signals is not None:
            try:
                client_signals = parse_client_signals(req.client_signals)
            except SignalsError:
                reasons.append(R.SIGNALS_MALFORMED)

        risk = None
        network = self._networks.network_key(req.client_ip)
        cohort = cohort_key(asdict(att.evidence), req.reported_ids) if att.ok and att.evidence else None
        # Every attempt counts, including ones that fail: a farm's failures are part of its burst.
        self._registry.record_fleet_event("enrollment", decision_id, None, network, cohort)
        fleet = self._registry.fleet_counts(network, cohort, self.policy.risk.fleet_window_seconds)
        if att.evidence is not None:
            evidence = asdict(att.evidence)
            keybox = None
            if att.ok and att.evidence.attestation_key_sha256:
                # Only fresh, verified ownership contributes to trusted key history.
                # Invalid nonce/identity submissions cannot poison another device.
                self._registry.record_attestation_key(
                    att.evidence.attestation_key_sha256, decision_id, device_model_key(evidence, req.reported_ids),
                )
                keybox = self._registry.attestation_key_stats(
                    att.evidence.attestation_key_sha256, self.policy.risk.keybox_window_seconds,
                )
            risk = assess(
                RiskInput(client_signals, play_signals, evidence, reported_ids=req.reported_ids, keybox=keybox,
                          fleet=fleet),
                self.policy.risk, self.policy.signing_cert_sha256, action_type=None, now=now,
            )
            if (risk_reason := _risk_reason(risk)) is not None:
                reasons.append(risk_reason)

        device_id = None
        # STEP_UP enrollments are registered: the bank verifies the customer
        # out-of-band, and every later action is still scored on its own.
        if decide(reasons) != BLOCK:
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
                            has_confirm_key=confirm is not None, risk=risk)

    def _confirm_key_reasons(self, device: AttestationResult, confirm: AttestationResult) -> list[str]:
        if not confirm.ok or confirm.evidence is None or device.evidence is None:
            return [R.CONFIRM_KEY_INVALID]
        out = []
        dev, con = device.evidence, confirm.evidence
        # These checks require consistent boot/model evidence and distinct keys.
        # They do NOT prove physical co-residency: same-model phones can share these facts.
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

        play_signals = self._check_play(
            req.play_integrity_token,
            action_request_hash(req.signed_data),
            action.action_type in p.play_integrity_required_actions,
            reasons,
            warnings,
            now,
        )

        client_signals = None
        if action.signals is not None:
            try:
                client_signals = parse_client_signals(action.signals)
            except SignalsError:
                reasons.append(R.SIGNALS_MALFORMED)
        now_s = now.timestamp() if now else time.time()
        network = self._networks.network_key(req.client_ip)
        # Invalid signatures cannot inflate the count of devices seen on a network.
        self._registry.record_fleet_event(
            "action" if decide(reasons) != BLOCK else "action_attempt",
            decision_id, req.device_id if decide(reasons) != BLOCK else None, network, None,
        )
        key_sha = record.evidence.get("attestation_key_sha256")
        risk = assess(
            RiskInput(
                client_signals,
                play_signals,
                record.evidence,
                device_age_seconds=now_s - record.enrolled_at,
                recent_actions=self._registry.count_recent_actions(req.device_id, p.risk.velocity_window_seconds),
                # Re-evaluated on every action: a keybox that leaks after this
                # device enrolled still flags it.
                keybox=self._registry.attestation_key_stats(key_sha, p.risk.keybox_window_seconds) if key_sha else None,
                fleet=self._registry.fleet_counts(network, None, p.risk.fleet_window_seconds),
            ),
            p.risk, p.signing_cert_sha256, action_type=action.action_type, now=now,
        )
        if (risk_reason := _risk_reason(risk)) is not None:
            reasons.append(risk_reason)
        return self._finish_action(decision_id, req, reasons, warnings, action, risk)

    def _finish_action(self, decision_id, req, reasons, warnings, action, risk=None) -> ActionDecision:
        reasons_t = tuple(dict.fromkeys(reasons))
        decision = decide(reasons_t)
        if decision == ALLOW:
            self._registry.touch(req.device_id)
        if self._registry.get(req.device_id) is not None:
            self._registry.record_decision(
                decision_id, req.device_id, "action", action.action_type if action else None, decision,
                risk.score if risk else None, list(risk.factors) if risk else [], list(reasons_t),
            )
        result = ActionDecision(
            decision=decision,
            decision_id=decision_id,
            reasons=reasons_t,
            warnings=tuple(dict.fromkeys(warnings)),
            action_type=action.action_type if action and decision == ALLOW else None,
            params=action.params if action and decision == ALLOW else None,
            risk=risk,
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
                    "risk_score": risk.score if risk else None,
                    "risk_factors": risk.factor_names() if risk else None,
                },
                sort_keys=True,
            )
        )
        return result

    def _finish(self, decision_id, reasons, warnings, device_id, evidence, play_signals,
                has_confirm_key=False, risk=None) -> EnrollmentDecision:
        reasons_t = tuple(dict.fromkeys(reasons))
        # A step-up that could not be registered (e.g. duplicate key) is a block.
        verdict = decide(reasons_t)
        if verdict == STEP_UP and device_id is None:
            verdict = BLOCK
        self._registry.record_decision(
            decision_id, device_id, "enrollment", None, verdict,
            risk.score if risk else None, list(risk.factors) if risk else [], list(reasons_t),
        )
        decision = EnrollmentDecision(
            decision=verdict,
            decision_id=decision_id,
            reasons=reasons_t,
            warnings=tuple(dict.fromkeys(warnings)),
            device_id=device_id,
            evidence=evidence,
            play_signals=play_signals,
            has_confirm_key=has_confirm_key and device_id is not None,
            risk=risk,
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
                    "risk_score": risk.score if risk else None,
                    "risk_factors": risk.factor_names() if risk else None,
                },
                sort_keys=True,
            )
        )
        return decision
