"""Trust decisions.

* Enrollment (Phase 1): hard-fail gates, ALLOW / BLOCK.
* Signed actions (Phase 2): the enrolled hardware key signs each sensitive
  action; ALLOW / STEP_UP / BLOCK.
* Risk scoring (Phase 3): client signals, fresh Play Integrity signals,
  hardware evidence and history add up to an explainable score that can
  turn an otherwise-clean request into STEP_UP or BLOCK. Hard gates always win.
* Server-verified scan (Run 17): the enrolled key signs a scan transcript with
  fresh attestation from an ephemeral key; the result is a traceable verdict
  plus a history comparison. A scan never authorises a business transaction.
* Key rotation (Run 17): the enrolled key authorises a new attested key; the
  device record keeps its ID and history, the old key is retired forever.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime

from . import reasons as R
from . import scan_evidence
from .evidence_history import (
    SOURCE_KEY_ROTATION,
    SOURCE_SCAN_REFRESH,
    VERIFIER_RULESET,
    compare_continuity,
    snapshot,
    source_of,
    summary,
)
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
from .enrollment_proof import validate_proof
from .key_description import AUTH_BIOMETRIC, AUTH_PASSWORD
from .lifecycle import (
    BINDING_BOUND,
    BINDING_LEGACY_UNBOUND,
    EVENT_PENDING_EXPIRED,
    EVENT_REVOKED,
    EVENT_STEP_UP_COMPLETED,
    REVOKE_REASONS,
    STATUS_ACTIVE,
    STATUS_PENDING,
    STATUS_REVOKED,
    STEP_UP_METHODS,
    Principal,
    owns,
)
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
_STEP_UP_REASONS = frozenset({R.CONFIRM_KEY_REQUIRED, R.RISK_STEP_UP, R.SCAN_DEVICE_EVIDENCE_CHANGED})


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
    evidence_data: bytes | None = None
    evidence_signature: bytes | None = None


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
    # Run 16: lifecycle status of the registered device ("active" / "pending").
    device_status: str | None = None


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
class ScanRequest:
    device_id: str
    challenge_id: str
    scan_data: bytes
    signature: bytes
    # Attestation chain of an ephemeral key generated with the scan nonce; None if not sent.
    fresh_chain: list[bytes] | None = None
    play_integrity_token: str | None = None


# Per-evidence status vocabulary of a scan result (Run 17).
VERIFIED = "VERIFIED"
FAILED = "FAILED"
UNAVAILABLE = "UNAVAILABLE"
NOT_PROVIDED = "NOT_PROVIDED"
SIGNED = "SIGNED"
MALFORMED = "MALFORMED"


@dataclass(frozen=True)
class ScanDecision:
    decision: str
    decision_id: str
    reasons: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    verified_at_ms: int = 0
    fresh_until_ms: int = 0
    policy_version: str = ""
    policy_digest: str = ""
    verifier_ruleset: str = VERIFIER_RULESET
    # deviceKeySignature / freshAttestation / playIntegrity / clientSignals -> status
    evidence: dict = field(default_factory=dict)
    history: dict | None = None
    risk: RiskResult | None = None


@dataclass(frozen=True)
class KeyRotationRequest:
    device_id: str
    challenge_id: str
    rotation_data: bytes
    old_key_signature: bytes
    new_key_signature: bytes
    new_chain: list[bytes]
    new_confirm_chain: list[bytes] | None = None
    # Run 28: Play Integrity token bound to the exact rotation transcript (key-rotation domain).
    play_integrity_token: str | None = None


@dataclass(frozen=True)
class KeyRotationDecision:
    decision: str
    decision_id: str
    reasons: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    rotated: bool = False
    has_confirm_key: bool = False
    risk: RiskResult | None = None


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

    def issue_challenge(self, principal: Principal | None = None) -> Challenge:
        """Enrollment challenge, bound to the requesting principal when there is one."""
        return self._challenges.issue(bound_to=principal.binding_key if principal else None)

    def _owned(self, device_id: str, principal: Principal | None):
        record = self._registry.get(device_id)
        if record is None or not owns(principal, record.owner_tenant, record.owner_account):
            return None
        return record

    def issue_action_challenge(self, device_id: str, principal: Principal | None = None) -> Challenge | None:
        """Challenge bound to one active device the principal owns; None otherwise (same answer for all)."""
        if self.policy.require_principal and principal is None:
            return None
        record = self._owned(device_id, principal)
        if record is None or not record.active:
            return None
        return self._challenges.issue(bound_to=device_id, ttl_seconds=self.policy.action_challenge_ttl_seconds)

    def _gate_reason(self, record) -> str | None:
        """Why a known, owned device may not act/scan/rotate now (None: it may)."""
        if record.status == STATUS_REVOKED:
            return R.DEVICE_REVOKED
        if record.status == STATUS_PENDING:
            return R.DEVICE_PENDING
        if self.policy.require_bound_device and record.binding != BINDING_BOUND:
            return R.DEVICE_REBINDING_REQUIRED
        return None

    def issue_device_challenge(self, device_id: str, purpose: str,
                               principal: Principal | None = None) -> Challenge | None:
        """Run 17 scan / key-rotation challenge; None for unknown, not-owned or non-active devices."""
        binding = scan_evidence.challenge_binding(purpose, device_id)
        if self.policy.require_principal and principal is None:
            return None
        record = self._owned(device_id, principal)
        if record is None or self._gate_reason(record) is not None:
            return None
        return self._challenges.issue(bound_to=binding, ttl_seconds=self.policy.scan_challenge_ttl_seconds)

    # --- lifecycle (Run 16) ---------------------------------------------------

    def device_status(self, device_id: str, principal: Principal | None) -> dict | None:
        """Minimal owner view: no evidence, no decisions, no backend reasons."""
        record = self._owned(device_id, principal)
        if record is None:
            return None
        return {"deviceId": record.device_id, "status": record.status, "binding": record.binding,
                "hasConfirmKey": record.confirm_key_spki is not None}

    def complete_step_up(self, device_id: str, method: str, *, principal: Principal | None = None,
                         actor: str = "gateway") -> str:
        """Authorised step-up completion: pending -> active.

        The caller (authenticated gateway for the owning principal, or an
        administrator) asserts that the account owner passed ``method``. This
        does not create device-key proof that the enrollment lacked.
        Returns "active", or "not_found" / "not_pending" / "expired".
        """
        if method not in STEP_UP_METHODS:
            raise ValueError("unknown step-up method")
        record = self._registry.get(device_id) if actor == "admin" else self._owned(device_id, principal)
        if record is None:
            return "not_found"
        if record.status != STATUS_PENDING:
            return "not_pending"
        since = record.state_changed_at if record.state_changed_at is not None else record.enrolled_at
        if self._registry_clock() - since > self.policy.pending_ttl_seconds:
            self._registry.transition(device_id, EVENT_PENDING_EXPIRED, "system", "PENDING_TTL")
            self._lifecycle_log(device_id, EVENT_PENDING_EXPIRED, "system")
            return "expired"
        if self._registry.transition(device_id, EVENT_STEP_UP_COMPLETED, actor, method) is None:
            return "not_pending"
        self._lifecycle_log(device_id, EVENT_STEP_UP_COMPLETED, actor)
        return STATUS_ACTIVE

    def revoke_owned_device(self, device_id: str, reason: str, principal: Principal | None) -> bool:
        """Owner-initiated revocation (lost phone, user request) through the gateway."""
        if reason not in REVOKE_REASONS:
            raise ValueError("unknown revoke reason")
        if self._owned(device_id, principal) is None:
            return False
        ok = self._registry.revoke(device_id, reason, actor="gateway")
        self._lifecycle_log(device_id, EVENT_REVOKED, "gateway")
        return ok

    def _registry_clock(self) -> float:
        return self._registry._clock()

    @staticmethod
    def _lifecycle_log(device_id: str, event: str, actor: str) -> None:
        log.info(json.dumps({"event": "device_lifecycle", "device_id": device_id, "transition": event,
                             "actor": actor}, sort_keys=True))

    def device_detail(self, device_id: str, limit: int = 50) -> dict | None:
        record = self._registry.get(device_id)
        if record is None:
            return None
        ev = record.evidence
        return {
            "deviceId": record.device_id,
            "status": record.status,
            "binding": record.binding,
            "owner": {"tenant": record.owner_tenant, "account": record.owner_account}
            if record.owner_account is not None else None,
            "lifecycle": self._registry.lifecycle_events(device_id),
            "enrolledAt": record.enrolled_at,
            "hasConfirmKey": record.confirm_key_spki is not None,
            "attested": {
                "securityLevel": ev.get("attestation_security_level"),
                "bootState": ev.get("verified_boot_state"),
                "osPatchLevel": ev.get("os_patch_level"),
                "brand": (ev.get("attested_ids") or {}).get("brand"),
                "model": (ev.get("attested_ids") or {}).get("model"),
            },
            "history": self._history_entries(device_id, 20),
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

    def device_history(self, device_id: str, principal: Principal | None, limit: int = 20) -> dict | None:
        """Owner view of attested history: summaries and comparison findings, no evidence JSON."""
        if self._owned(device_id, principal) is None:
            return None
        return {"deviceId": device_id, "snapshots": self._history_entries(device_id, limit)}

    def _history_entries(self, device_id: str, limit: int) -> list[dict]:
        rows = self._registry.assurance_history(device_id, limit + 1)  # +1: compare the oldest shown
        out = []
        for i, row in enumerate(rows[:limit]):
            older = rows[i + 1] if i + 1 < len(rows) else None
            out.append({"at": row["at"], **summary(row["evidence"]),
                        "changes": compare_continuity(older["evidence"], row["evidence"]) if older else []})
        return out

    def fleet_summary(self, window_seconds: float | None = None, limit: int = 10) -> dict:
        return self._registry.fleet_summary(window_seconds or 24 * 3600, limit)

    def revoke_device(self, device_id: str, reason: str) -> bool:
        revoked = self._registry.revoke(device_id, reason, actor="admin")
        log.info(json.dumps({"event": "device_revoked", "device_id": device_id, "found": revoked, "reason": reason}))
        return revoked

    def enroll(self, req: EnrollmentRequest, now: datetime | None = None,
               principal: Principal | None = None) -> EnrollmentDecision:
        decision_id = "dec_" + secrets.token_urlsafe(12)
        nonce = self._challenges.consume(req.challenge_id, bound_to=principal.binding_key if principal else None)
        if self.policy.require_principal and principal is None:
            return self._finish(decision_id, [R.PRINCIPAL_REQUIRED], [], None, None, None)
        if nonce is None:
            return self._finish(decision_id, [R.CHALLENGE_UNKNOWN], [], None, None, None)

        att = self._verifier.verify(req.attestation_chain, nonce, req.reported_ids, now=now)
        reasons = list(att.reasons)
        warnings: list[str] = list(att.notes)
        play_signals = None
        expected_play_hash = enrollment_request_hash(nonce, att.leaf_public_key_spki or b"")
        proof_ok = False
        proof_present = req.evidence_data is not None or req.evidence_signature is not None
        if proof_present:
            try:
                expected_play_hash = validate_proof(
                    req.evidence_data, req.evidence_signature, att.leaf_public_key_spki,
                    req.challenge_id, nonce, req.attestation_chain, req.confirm_key_chain,
                    req.reported_ids, req.client_signals,
                )
                proof_ok = True
            except (ValueError, TypeError):
                reasons.append(R.ENROLLMENT_PROOF_INVALID)
        elif self.policy.require_bound_enrollment:
            reasons.append(R.ENROLLMENT_PROOF_MISSING)
        else:
            warnings.append(R.ENROLLMENT_LEGACY_UNBOUND)

        if att.leaf_public_key_spki is not None:
            play_signals = self._check_play(
                req.play_integrity_token,
                expected_play_hash,
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
            if att.ok and (proof_ok or not self.policy.require_bound_enrollment and not proof_present) and att.evidence.attestation_key_sha256:
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
        device_status = None
        # Run 16: STEP_UP enrollments are registered as *pending* and cannot act
        # until an authenticated step-up completion; unbound legacy enrollments
        # follow policy. The same attested key can never enroll twice, so a
        # revoked identity is not revived by enrolling again.
        verdict = decide(reasons)
        if verdict != BLOCK:
            binding = BINDING_BOUND if proof_ok else BINDING_LEGACY_UNBOUND
            pending = verdict == STEP_UP or (
                binding != BINDING_BOUND and self.policy.unbound_enrollment_state == STATUS_PENDING)
            device_status = STATUS_PENDING if pending else STATUS_ACTIVE
            try:
                device_id = self._registry.register(
                    att.leaf_public_key_spki,
                    att.evidence,
                    play_signals,
                    confirm_key_spki=confirm.leaf_public_key_spki if confirm else None,
                    confirm_evidence=confirm.evidence if confirm else None,
                    status=device_status,
                    owner_tenant=principal.tenant if principal else None,
                    owner_account=principal.account if principal else None,
                    binding=binding,
                )
            except DuplicateDeviceKey:
                reasons.append(R.KEY_ALREADY_ENROLLED)
                device_status = None
        return self._finish(decision_id, reasons, warnings, device_id, att.evidence, play_signals,
                            has_confirm_key=confirm is not None, risk=risk, device_status=device_status)

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

    # --- Run 17: server-verified scan -----------------------------------------

    def _transcript_reasons(self, doc, device_id, challenge_id, nonce, now) -> list[str]:
        out = []
        if doc.device_id != device_id or doc.challenge_id != challenge_id or doc.nonce != b64url(nonce):
            out.append(R.SCAN_EVIDENCE_MISMATCH)
        now_ms = int((now.timestamp() if now else time.time()) * 1000)
        if (doc.timestamp_ms > now_ms + self.policy.clock_skew_seconds * 1000
                or now_ms - doc.timestamp_ms > self.policy.scan_max_age_seconds * 1000):
            out.append(R.SCAN_STALE)
        return out

    def verify_scan(self, req: ScanRequest, now: datetime | None = None,
                    principal: Principal | None = None) -> ScanDecision:
        """Verify one server scan. Authenticates the transcript before any attestation or Play work."""
        decision_id = "dec_" + secrets.token_urlsafe(12)
        evidence = {"deviceKeySignature": NOT_PROVIDED, "freshAttestation": NOT_PROVIDED,
                    "playIntegrity": NOT_PROVIDED, "clientSignals": NOT_PROVIDED}
        # Burn the challenge first so it can never be retried, whatever happens next.
        nonce = self._challenges.consume(
            req.challenge_id, bound_to=scan_evidence.challenge_binding(scan_evidence.PURPOSE_SCAN, req.device_id))

        def finish(reasons, warnings=(), history=None, risk=None, record_known=True):
            return self._finish_scan(decision_id, req.device_id if record_known else None, reasons, warnings,
                                     evidence, history, risk, now)

        if self.policy.require_principal and principal is None:
            return finish([R.PRINCIPAL_REQUIRED], record_known=False)
        record = self._owned(req.device_id, principal)
        if record is None:
            return finish([R.DEVICE_UNKNOWN], record_known=False)
        if (gate := self._gate_reason(record)) is not None:
            return finish([gate])
        if nonce is None:
            return finish([R.CHALLENGE_UNKNOWN])
        try:
            doc = scan_evidence.parse(req.scan_data, scan_evidence.PURPOSE_SCAN)
        except ValueError:
            return finish([R.SCAN_EVIDENCE_MALFORMED])
        reasons = self._transcript_reasons(doc, req.device_id, req.challenge_id, nonce, now)
        if doc.chain_sha256 != scan_evidence.chain_digests(req.fresh_chain):
            reasons.append(R.SCAN_EVIDENCE_MISMATCH)
        signature_ok = verify_signature(record.public_key_spki, req.scan_data, req.signature)
        evidence["deviceKeySignature"] = VERIFIED if signature_ok else FAILED
        if not signature_ok:
            reasons.append(R.SIGNATURE_INVALID)
        if reasons:
            # Unauthenticated or mis-bound: no attestation, Play or history work is done for it.
            return finish(reasons)

        warnings: list[str] = []
        fresh = None
        if req.fresh_chain:
            att = self._verifier.verify(req.fresh_chain, nonce, doc.device, now=now)
            reasons.extend(att.reasons)
            warnings.extend(att.notes)
            leaf_sha = att.evidence.leaf_spki_sha256 if att.evidence else None
            reused = leaf_sha is not None and self._registry.key_known(leaf_sha)
            if reused:
                reasons.append(R.FRESH_ATTESTATION_KEY_REUSED)
            if att.ok and not reused:
                fresh = att
            evidence["freshAttestation"] = VERIFIED if fresh is not None else FAILED
        elif self.policy.scan_require_fresh_attestation:
            reasons.append(R.SCAN_FRESH_ATTESTATION_MISSING)

        play_before = len(reasons)
        play_signals = self._check_play(req.play_integrity_token,
                                        scan_evidence.request_hash(scan_evidence.PURPOSE_SCAN, req.scan_data),
                                        self.policy.scan_require_play_integrity, reasons, warnings, now)
        if req.play_integrity_token:
            evidence["playIntegrity"] = (UNAVAILABLE if play_signals is None
                                         else FAILED if len(reasons) > play_before else VERIFIED)

        client_signals = None
        if doc.signals is not None:
            try:
                client_signals = parse_client_signals(doc.signals)
                evidence["clientSignals"] = SIGNED
            except SignalsError:
                reasons.append(R.SIGNALS_MALFORMED)
                evidence["clientSignals"] = MALFORMED

        attested = asdict(fresh.evidence) if fresh is not None else record.evidence
        key_sha = attested.get("attestation_key_sha256")
        now_s = now.timestamp() if now else time.time()
        risk = assess(
            RiskInput(client_signals, play_signals, attested, device_age_seconds=now_s - record.enrolled_at,
                      # Read-only: scans never add to a keybox's enrollment history.
                      keybox=self._registry.attestation_key_stats(key_sha, self.policy.risk.keybox_window_seconds)
                      if key_sha else None),
            self.policy.risk, self.policy.signing_cert_sha256, action_type=None, now=now,
        )
        if (risk_reason := _risk_reason(risk)) is not None:
            reasons.append(risk_reason)

        history = self._scan_history(record, fresh)
        if self.policy.scan_history_review == "step_up" and any(c["level"] == "REVIEW" for c in history["changes"]):
            # Run 28: fresh hardware evidence that contradicts the enrolled device is never
            # presented as a plain "trusted" verdict.
            reasons.append(R.SCAN_DEVICE_EVIDENCE_CHANGED)
        return finish(reasons, warnings, history, risk)

    @staticmethod
    def _enrolled_baseline(record) -> dict:
        """The current key's own attested evidence, as a v1 snapshot-shaped dict.

        Run 28: the decision baseline. The latest history row may itself be a refresh,
        so comparing only with it would let one contradicting scan become the reference
        for the next one.
        """
        ev = dict(record.evidence)
        ids = {k: v for k, v in (ev.get("attested_ids") or {}).items()
               if k in {"brand", "device", "product", "manufacturer", "model"}}
        return {**ev, "v": 1, "attested_ids": ids,
                "device_key_sha256": hashlib.sha256(record.public_key_spki).hexdigest()}

    def _scan_history(self, record, fresh: AttestationResult | None) -> dict:
        """Persist a verified refresh snapshot (if any); compare it with the latest snapshot
        and with the enrolled key's attested evidence (REVIEW findings from either count)."""
        rows = self._registry.assurance_history(record.device_id, 1)
        previous = rows[0] if rows else None
        out = {"snapshots": None, "previousAt": previous["at"] if previous else None,
               "previousSource": source_of(previous["evidence"]) if previous else None,
               "compared": False, "changes": []}
        if fresh is not None:
            current = snapshot(fresh.evidence, fresh.leaf_public_key_spki, source=SOURCE_SCAN_REFRESH,
                               device_key_sha256=hashlib.sha256(record.public_key_spki).hexdigest())
            if previous is not None:
                out["changes"] = compare_continuity(previous["evidence"], current)
                out["compared"] = True
            seen = {(c["code"], c["field"]) for c in out["changes"]}
            for change in compare_continuity(self._enrolled_baseline(record), current):
                if change["level"] == "REVIEW" and (change["code"], change["field"]) not in seen:
                    out["changes"].append(change)
                    out["compared"] = True
            self._registry.record_snapshot(record.device_id, current, self.policy.history_max_snapshots)
        out["snapshots"] = len(self._registry.assurance_history(record.device_id, 100))
        return out

    def _finish_scan(self, decision_id, device_id, reasons, warnings, evidence, history, risk, now) -> ScanDecision:
        reasons_t = tuple(dict.fromkeys(reasons))
        decision = decide(reasons_t)
        verified_at_ms = int((now.timestamp() if now else time.time()) * 1000)
        if device_id is not None:
            self._registry.record_decision(decision_id, device_id, "scan", None, decision,
                                           risk.score if risk else None, list(risk.factors) if risk else [],
                                           list(reasons_t))
        result = ScanDecision(
            decision=decision, decision_id=decision_id, reasons=reasons_t,
            warnings=tuple(dict.fromkeys(warnings)), verified_at_ms=verified_at_ms,
            fresh_until_ms=verified_at_ms + self.policy.scan_result_ttl_seconds * 1000,
            policy_version=self.policy.policy_version, policy_digest=self.policy.digest(),
            evidence=dict(evidence), history=history, risk=risk,
        )
        log.info(json.dumps({
            "event": "scan", "decision_id": decision_id, "decision": decision, "reasons": list(reasons_t),
            "warnings": list(result.warnings), "device_id": device_id, "evidence": result.evidence,
            "history_changes": [c["code"] for c in (history or {}).get("changes", [])],
            "risk_score": risk.score if risk else None, "risk_factors": risk.factor_names() if risk else None,
        }, sort_keys=True))
        return result

    # --- Run 17: key rotation ---------------------------------------------------

    def rotate_key(self, req: KeyRotationRequest, now: datetime | None = None,
                   principal: Principal | None = None) -> KeyRotationDecision:
        """The enrolled key authorises a new attested key. Only ALLOW changes anything."""
        decision_id = "dec_" + secrets.token_urlsafe(12)
        nonce = self._challenges.consume(
            req.challenge_id,
            bound_to=scan_evidence.challenge_binding(scan_evidence.PURPOSE_KEY_ROTATION, req.device_id))

        def finish(reasons, warnings=(), *, rotated=False, has_confirm=False, risk=None, known=True):
            return self._finish_rotation(decision_id, req.device_id if known else None, reasons, warnings,
                                         rotated, has_confirm, risk)

        if self.policy.require_principal and principal is None:
            return finish([R.PRINCIPAL_REQUIRED], known=False)
        record = self._owned(req.device_id, principal)
        if record is None:
            return finish([R.DEVICE_UNKNOWN], known=False)
        if (gate := self._gate_reason(record)) is not None:
            return finish([gate])
        if nonce is None:
            return finish([R.CHALLENGE_UNKNOWN])
        try:
            doc = scan_evidence.parse(req.rotation_data, scan_evidence.PURPOSE_KEY_ROTATION)
        except ValueError:
            return finish([R.SCAN_EVIDENCE_MALFORMED])
        reasons = self._transcript_reasons(doc, req.device_id, req.challenge_id, nonce, now)
        if (doc.chain_sha256 != scan_evidence.chain_digests(req.new_chain)
                or doc.confirm_chain_sha256 != scan_evidence.chain_digests(req.new_confirm_chain)):
            reasons.append(R.SCAN_EVIDENCE_MISMATCH)
        if not verify_signature(record.public_key_spki, req.rotation_data, req.old_key_signature):
            reasons.append(R.SIGNATURE_INVALID)
        if reasons:
            return finish(reasons)

        att = self._verifier.verify(req.new_chain, nonce, doc.device, now=now)
        reasons = list(att.reasons)
        warnings = list(att.notes)
        new_spki = att.leaf_public_key_spki
        if new_spki is None or not verify_signature(new_spki, req.rotation_data, req.new_key_signature):
            reasons.append(R.KEY_ROTATION_PROOF_INVALID)
        if att.evidence is not None and self._registry.key_known(att.evidence.leaf_spki_sha256):
            reasons.append(R.KEY_ALREADY_ENROLLED)
        if att.evidence is not None and new_spki is not None:
            # Run 28: rotation keeps one enrolled phone's identity. A new key whose attestation
            # contradicts the enrolled evidence (other model, boot key, lock state, older
            # patch) is not a same-phone rotation; recovery is an authenticated new enrollment.
            candidate = snapshot(att.evidence, new_spki, source=SOURCE_KEY_ROTATION,
                                 authorized_by_sha256=hashlib.sha256(record.public_key_spki).hexdigest())
            if any(c["level"] == "REVIEW" for c in compare_continuity(self._enrolled_baseline(record), candidate)):
                reasons.append(R.KEY_ROTATION_DEVICE_CHANGED)
        # Run 28: the key that gets registered meets the same Play requirement as at enrollment.
        play_signals = None
        if new_spki is not None:
            play_signals = self._check_play(
                req.play_integrity_token,
                scan_evidence.request_hash(scan_evidence.PURPOSE_KEY_ROTATION, req.rotation_data),
                self.policy.require_play_integrity, reasons, warnings, now)
        confirm = None
        if req.new_confirm_chain:
            confirm = self._verifier.verify(req.new_confirm_chain, nonce, doc.device, now=now)
            reasons.extend(self._confirm_key_reasons(att, confirm))
            if confirm.evidence is not None and self._registry.key_known(confirm.evidence.leaf_spki_sha256):
                reasons.append(R.CONFIRM_KEY_INVALID)

        risk = None
        if att.evidence is not None:
            new_evidence = asdict(att.evidence)
            keybox = None
            if not reasons and att.evidence.attestation_key_sha256:
                # As at enrollment: only fresh, verified ownership contributes to key history.
                self._registry.record_attestation_key(
                    att.evidence.attestation_key_sha256, decision_id, device_model_key(new_evidence, doc.device))
                keybox = self._registry.attestation_key_stats(
                    att.evidence.attestation_key_sha256, self.policy.risk.keybox_window_seconds)
            now_s = now.timestamp() if now else time.time()
            risk = assess(RiskInput(None, play_signals, new_evidence, device_age_seconds=now_s - record.enrolled_at,
                                    reported_ids=doc.device, keybox=keybox),
                          self.policy.risk, self.policy.signing_cert_sha256, action_type=None, now=now)
            if (risk_reason := _risk_reason(risk)) is not None:
                reasons.append(risk_reason)

        if decide(reasons) != ALLOW:
            # STEP_UP and BLOCK change nothing: recovery is an authenticated new enrollment.
            return finish(reasons, warnings, risk=risk)
        try:
            rotated = self._registry.rotate_key(
                req.device_id, hashlib.sha256(record.public_key_spki).hexdigest(), new_spki, att.evidence,
                confirm.leaf_public_key_spki if confirm else None, confirm.evidence if confirm else None)
        except DuplicateDeviceKey:
            return finish(reasons + [R.KEY_ALREADY_ENROLLED], warnings, risk=risk)
        if not rotated:
            return finish(reasons + [R.KEY_ROTATION_CONFLICT], warnings, risk=risk)
        self._lifecycle_log(req.device_id, "key_rotated", "system")
        return finish(reasons, warnings, rotated=True, has_confirm=confirm is not None, risk=risk)

    def _finish_rotation(self, decision_id, device_id, reasons, warnings, rotated, has_confirm,
                         risk) -> KeyRotationDecision:
        reasons_t = tuple(dict.fromkeys(reasons))
        decision = decide(reasons_t) if rotated or reasons_t else BLOCK
        if device_id is not None:
            self._registry.record_decision(decision_id, device_id, "key_rotation", None, decision,
                                           risk.score if risk else None, list(risk.factors) if risk else [],
                                           list(reasons_t))
        log.info(json.dumps({"event": "key_rotation", "decision_id": decision_id, "decision": decision,
                             "rotated": rotated, "reasons": list(reasons_t), "device_id": device_id,
                             "risk_score": risk.score if risk else None}, sort_keys=True))
        return KeyRotationDecision(decision, decision_id, reasons_t, tuple(dict.fromkeys(warnings)), rotated,
                                   has_confirm and rotated, risk)

    # --- Phase 2: signed actions ---------------------------------------------

    def verify_action(self, req: ActionRequest, now: datetime | None = None,
                      principal: Principal | None = None) -> ActionDecision:
        decision_id = "dec_" + secrets.token_urlsafe(12)
        reasons: list[str] = []
        warnings: list[str] = []
        # Burn the challenge first so it can never be retried, whatever happens next.
        nonce = self._challenges.consume(req.challenge_id, bound_to=req.device_id)
        if self.policy.require_principal and principal is None:
            return self._finish_action(decision_id, req, [R.PRINCIPAL_REQUIRED], warnings, None)
        record = self._owned(req.device_id, principal)
        if record is None:
            # Unknown and not-owned devices get the same answer.
            return self._finish_action(decision_id, req, [R.DEVICE_UNKNOWN], warnings, None)
        if (gate := self._gate_reason(record)) is not None:
            return self._finish_action(decision_id, req, [gate], warnings, None)
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
                has_confirm_key=False, risk=None, device_status=None) -> EnrollmentDecision:
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
            device_status=device_status if device_id is not None else None,
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
