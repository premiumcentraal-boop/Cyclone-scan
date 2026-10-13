"""Phase 1 enrollment decision: hard-fail gates only (ALLOW / BLOCK)."""

from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime

from . import reasons as R
from .attestation import AttestationEvidence, AttestationVerifier
from .challenges import Challenge, ChallengeStore
from .play_integrity import DecodeError, IntegrityTokenDecoder, enrollment_request_hash, evaluate_payload
from .policy import TrustPolicy
from .registry import DeviceRegistry, DuplicateDeviceKey

log = logging.getLogger("device_trust.decisions")

ALLOW = "ALLOW"
BLOCK = "BLOCK"


@dataclass(frozen=True)
class EnrollmentRequest:
    challenge_id: str
    attestation_chain: list[bytes]
    reported_ids: dict[str, str]
    play_integrity_token: str | None = None


@dataclass(frozen=True)
class EnrollmentDecision:
    decision: str
    decision_id: str
    reasons: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    device_id: str | None = None
    evidence: AttestationEvidence | None = None
    play_signals: dict | None = field(default=None)


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

    def enroll(self, req: EnrollmentRequest, now: datetime | None = None) -> EnrollmentDecision:
        decision_id = "dec_" + secrets.token_urlsafe(12)
        nonce = self._challenges.consume(req.challenge_id)
        if nonce is None:
            return self._finish(decision_id, [R.CHALLENGE_UNKNOWN], [], None, None, None)

        att = self._verifier.verify(req.attestation_chain, nonce, req.reported_ids, now=now)
        reasons = list(att.reasons)
        warnings: list[str] = []
        play_signals = None

        if req.play_integrity_token and att.leaf_public_key_spki is not None:
            if self._play is None:
                (reasons if self.policy.require_play_integrity else warnings).append(R.PLAY_INTEGRITY_UNAVAILABLE)
            else:
                try:
                    payload = self._play.decode(self.policy.package_name, req.play_integrity_token)
                except DecodeError:
                    (reasons if self.policy.require_play_integrity else warnings).append(R.PLAY_INTEGRITY_UNAVAILABLE)
                else:
                    expected = enrollment_request_hash(nonce, att.leaf_public_key_spki)
                    now_ms = int(now.timestamp() * 1000) if now else None
                    play = evaluate_payload(payload, self.policy, expected, now_ms)
                    reasons.extend(play.reasons)
                    play_signals = play.signals
        elif not req.play_integrity_token and self.policy.require_play_integrity:
            reasons.append(R.PLAY_INTEGRITY_MISSING)

        device_id = None
        if not reasons:
            try:
                device_id = self._registry.register(att.leaf_public_key_spki, att.evidence, play_signals)
            except DuplicateDeviceKey:
                reasons.append(R.KEY_ALREADY_ENROLLED)
        return self._finish(decision_id, reasons, warnings, device_id, att.evidence, play_signals)

    def _finish(self, decision_id, reasons, warnings, device_id, evidence, play_signals) -> EnrollmentDecision:
        reasons_t = tuple(dict.fromkeys(reasons))
        decision = EnrollmentDecision(
            decision=ALLOW if not reasons_t else BLOCK,
            decision_id=decision_id,
            reasons=reasons_t,
            warnings=tuple(dict.fromkeys(warnings)),
            device_id=device_id,
            evidence=evidence,
            play_signals=play_signals,
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
                },
                sort_keys=True,
            )
        )
        return decision
