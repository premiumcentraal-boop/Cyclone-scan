"""HTTP API (FastAPI).

Deploy behind the bank backend / API gateway: the app should reach these
endpoints only through an authenticated session. By default responses do not
include failure reasons, so attackers cannot use the API as a bypass oracle;
operators look reasons up in the decision log by ``decisionId``.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request

from . import __version__
from pydantic import BaseModel, ConfigDict, Field

from .actions import MAX_SIGNED_DATA_BYTES
from .enrollment_proof import MAX_PROOF_BYTES
from .challenges import Challenge, ChallengeCapacityExceeded
from .lifecycle import REVOKE_REASONS, STEP_UP_METHODS, Principal
from .play_integrity import b64url
from .scan_evidence import MAX_TRANSCRIPT_BYTES, PURPOSES
from .service import ActionRequest, DeviceTrustService, EnrollmentRequest, KeyRotationRequest, ScanRequest

MAX_CERT_B64_CHARS = 16 * 1024
MAX_TOKEN_CHARS = 16 * 1024
ID_FIELDS = ("brand", "device", "product", "manufacturer", "model")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ChallengeResponse(_Model):
    challenge_id: str = Field(alias="challengeId")
    nonce: str
    expires_at: int = Field(alias="expiresAt")


class ReportedDevice(_Model):
    brand: str = Field(default="", max_length=128)
    device: str = Field(default="", max_length=128)
    product: str = Field(default="", max_length=128)
    manufacturer: str = Field(default="", max_length=128)
    model: str = Field(default="", max_length=128)


class EnrollmentBody(_Model):
    challenge_id: str = Field(alias="challengeId", min_length=1, max_length=128)
    attestation_chain: list[str] = Field(alias="attestationChain", min_length=1, max_length=10)
    play_integrity_token: str | None = Field(default=None, alias="playIntegrityToken", max_length=MAX_TOKEN_CHARS)
    device: ReportedDevice = Field(default_factory=ReportedDevice)
    confirm_key_chain: list[str] | None = Field(default=None, alias="confirmKeyChain", min_length=1, max_length=10)
    # Client signal report (signals.py); validated by the service.
    signals: dict | None = None
    evidence_data: str | None = Field(default=None, alias="evidenceData", max_length=MAX_PROOF_BYTES * 2)
    evidence_signature: str | None = Field(default=None, alias="evidenceSignature", max_length=1024)


class RiskFactorOut(_Model):
    factor: str
    points: int


class RiskOut(_Model):
    score: int
    factors: list[RiskFactorOut]
    # Run 14: counts of client check states (DETECTED / NOT_DETECTED /
    # UNAVAILABLE / UNSUPPORTED / UNREPORTED). Explanatory only.
    coverage: dict[str, int] | None = None


def _risk_out(risk) -> RiskOut | None:
    if risk is None:
        return None
    coverage = dict(risk.coverage) if getattr(risk, "coverage", None) is not None else None
    return RiskOut(score=risk.score, factors=[RiskFactorOut(factor=f, points=p) for f, p in risk.factors],
                   coverage=coverage)


class EnrollmentResponse(_Model):
    decision: str
    decision_id: str = Field(alias="decisionId")
    device_id: str | None = Field(default=None, alias="deviceId")
    # Run 16: "active" or "pending" (awaiting authenticated step-up completion).
    device_status: str | None = Field(default=None, alias="deviceStatus")
    reasons: list[str] | None = None
    warnings: list[str] | None = None
    risk: RiskOut | None = None


class ActionChallengeBody(_Model):
    device_id: str = Field(alias="deviceId", min_length=1, max_length=128)


class ActionBody(_Model):
    device_id: str = Field(alias="deviceId", min_length=1, max_length=128)
    challenge_id: str = Field(alias="challengeId", min_length=1, max_length=128)
    signed_data: str = Field(alias="signedData", min_length=1, max_length=MAX_SIGNED_DATA_BYTES * 2)
    signature: str = Field(min_length=1, max_length=512)
    key: Literal["device", "confirm"] = "device"
    play_integrity_token: str | None = Field(default=None, alias="playIntegrityToken", max_length=MAX_TOKEN_CHARS)


class SignedActionOut(_Model):
    type: str
    params: dict


class ActionResponse(_Model):
    decision: str
    decision_id: str = Field(alias="decisionId")
    action: SignedActionOut | None = None
    reasons: list[str] | None = None
    warnings: list[str] | None = None
    risk: RiskOut | None = None


class RevokeBody(_Model):
    reason: str = Field(min_length=1, max_length=200)


class StepUpCompletionBody(_Model):
    # The method the customer's backend used to verify the account owner.
    method: Literal[tuple(sorted(STEP_UP_METHODS))]  # type: ignore[valid-type]


class OwnerRevokeBody(_Model):
    reason: Literal[tuple(sorted(REVOKE_REASONS))]  # type: ignore[valid-type]


class DeviceStatusOut(_Model):
    device_id: str = Field(alias="deviceId")
    status: str
    binding: str
    has_confirm_key: bool = Field(alias="hasConfirmKey")


class DeviceChallengeBody(_Model):
    device_id: str = Field(alias="deviceId", min_length=1, max_length=128)
    purpose: Literal[PURPOSES]  # type: ignore[valid-type]


class ScanBody(_Model):
    device_id: str = Field(alias="deviceId", min_length=1, max_length=128)
    challenge_id: str = Field(alias="challengeId", min_length=1, max_length=128)
    scan_data: str = Field(alias="scanData", min_length=1, max_length=MAX_TRANSCRIPT_BYTES * 2)
    signature: str = Field(min_length=1, max_length=1024)
    fresh_attestation_chain: list[str] | None = Field(default=None, alias="freshAttestationChain",
                                                      min_length=1, max_length=10)
    play_integrity_token: str | None = Field(default=None, alias="playIntegrityToken", max_length=MAX_TOKEN_CHARS)


class ScanPolicyOut(_Model):
    version: str
    digest: str
    verifier_ruleset: str = Field(alias="verifierRuleset")


class HistoryChangeOut(_Model):
    code: str
    level: str
    field: str


class ScanHistoryOut(_Model):
    snapshots: int
    previous_at: float | None = Field(default=None, alias="previousAt")
    previous_source: str | None = Field(default=None, alias="previousSource")
    compared: bool
    changes: list[HistoryChangeOut]


class ScanResponse(_Model):
    decision: str
    decision_id: str = Field(alias="decisionId")
    verified_at: int = Field(alias="verifiedAt")
    fresh_until: int = Field(alias="freshUntil")
    policy: ScanPolicyOut
    evidence: dict[str, str]
    # Run 14 client check coverage counts; explanatory only.
    coverage: dict[str, int] | None = None
    history: ScanHistoryOut | None = None
    reasons: list[str] | None = None
    warnings: list[str] | None = None
    risk: RiskOut | None = None


class KeyRotationBody(_Model):
    device_id: str = Field(alias="deviceId", min_length=1, max_length=128)
    challenge_id: str = Field(alias="challengeId", min_length=1, max_length=128)
    rotation_data: str = Field(alias="rotationData", min_length=1, max_length=MAX_TRANSCRIPT_BYTES * 2)
    old_key_signature: str = Field(alias="oldKeySignature", min_length=1, max_length=1024)
    new_key_signature: str = Field(alias="newKeySignature", min_length=1, max_length=1024)
    new_attestation_chain: list[str] = Field(alias="newAttestationChain", min_length=1, max_length=10)
    new_confirm_key_chain: list[str] | None = Field(default=None, alias="newConfirmKeyChain",
                                                    min_length=1, max_length=10)


class KeyRotationResponse(_Model):
    decision: str
    decision_id: str = Field(alias="decisionId")
    rotated: bool
    has_confirm_key: bool | None = Field(default=None, alias="hasConfirmKey")
    reasons: list[str] | None = None
    warnings: list[str] | None = None
    risk: RiskOut | None = None


def _b64(value: str, field: str) -> bytes:
    try:
        normalized = value.strip().replace("-", "+").replace("_", "/")
        return base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=422, detail=f"{field} must be base64") from None


def _challenge_response(c: Challenge) -> ChallengeResponse:
    return ChallengeResponse(challengeId=c.challenge_id, nonce=b64url(c.nonce), expiresAt=int(c.expires_at))


def _decode_chain(items: list[str]) -> list[bytes]:
    out = []
    for item in items:
        if len(item) > MAX_CERT_B64_CHARS:
            raise HTTPException(status_code=422, detail="certificate too large")
        try:
            # Accept standard or URL-safe base64, with or without padding.
            normalized = item.strip().replace("-", "+").replace("_", "/")
            out.append(base64.b64decode(normalized + "=" * (-len(normalized) % 4), validate=True))
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=422, detail="attestationChain must be base64 DER") from None
    return out


def create_app(
    service: DeviceTrustService,
    *,
    expose_reasons: bool = False,
    admin_token: str | None = None,
    trust_forwarded_for: bool = False,
    gateway_token: str | None = None,
    public: bool = True,
) -> FastAPI:
    """Build the API. ``admin_token`` enables the admin endpoints; without it they are absent.

    ``public=False`` (Run 18, ``device-trust serve-admin``) builds an admin-only app with
    no client endpoints, to run on a separate internal listener so the admin interface is
    never reachable through the public client path. ``public=True`` with no admin token
    builds the client-only app.

    ``gateway_token`` (Run 16): the service sits behind the customer's backend,
    which authenticates the user and forwards the request with
    ``X-Gateway-Authorization: Bearer <gateway_token>``, ``X-Tenant-Id`` and
    ``X-Account-Id``. Only then are tenant/account trusted; account headers
    from anyone else are ignored. With a gateway token every device endpoint
    requires it, and the owner endpoints (/v1/devices/...) exist.

    ``trust_forwarded_for``: take the client IP from the first X-Forwarded-For
    entry. Enable only behind a proxy that sets it, otherwise callers can forge it.
    """

    def client_ip(request: Request) -> str | None:
        if trust_forwarded_for:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded.strip():
                return forwarded.split(",")[0].strip()
        return request.client.host if request.client else None

    if not public and not admin_token:
        raise ValueError("an admin-only app needs an admin token")
    app = FastAPI(title="Device Trust Service" if public else "Device Trust Service (admin)", version=__version__)

    def principal(request: Request) -> Principal | None:
        if not gateway_token:
            return None  # development / single-tenant mode: no principal is ever trusted
        auth = request.headers.get("x-gateway-authorization", "")
        if not hmac.compare_digest(auth.encode(), f"Bearer {gateway_token}".encode()):
            raise HTTPException(status_code=401, detail="unauthorized")
        try:
            return Principal(request.headers.get("x-tenant-id", ""), request.headers.get("x-account-id", ""))
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid principal") from None

    def _step_up_http(outcome: str) -> None:
        if outcome == "not_found":
            raise HTTPException(status_code=404, detail="device not found")
        if outcome == "not_pending":
            raise HTTPException(status_code=409, detail="device is not awaiting step-up")
        if outcome == "expired":
            raise HTTPException(status_code=410, detail="pending enrollment expired; enroll again")

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    if public:
        @app.post("/v1/challenges", status_code=201, response_model=ChallengeResponse, response_model_by_alias=True)
        def create_challenge(request: Request) -> ChallengeResponse:
            who = principal(request)
            try:
                c = service.issue_challenge(who)
            except ChallengeCapacityExceeded:
                raise HTTPException(status_code=503, detail="try again later") from None
            return _challenge_response(c)

        @app.post("/v1/enrollments", response_model=EnrollmentResponse, response_model_by_alias=True,
                  response_model_exclude_none=True)
        def enroll(body: EnrollmentBody, request: Request) -> EnrollmentResponse:
            reported = body.device.model_dump()
            req = EnrollmentRequest(
                challenge_id=body.challenge_id,
                attestation_chain=_decode_chain(body.attestation_chain),
                reported_ids={k: reported[k] for k in ID_FIELDS if reported[k]},
                play_integrity_token=body.play_integrity_token,
                confirm_key_chain=_decode_chain(body.confirm_key_chain) if body.confirm_key_chain else None,
                client_signals=body.signals,
                evidence_data=_b64(body.evidence_data, "evidenceData") if body.evidence_data is not None else None,
                evidence_signature=_b64(body.evidence_signature, "evidenceSignature") if body.evidence_signature is not None else None,
                client_ip=client_ip(request),
            )
            result = service.enroll(req, principal=principal(request))
            return EnrollmentResponse(
                decision=result.decision,
                decisionId=result.decision_id,
                deviceId=result.device_id,
                deviceStatus=result.device_status,
                reasons=list(result.reasons) if expose_reasons else None,
                warnings=list(result.warnings) if expose_reasons else None,
                risk=_risk_out(result.risk) if expose_reasons else None,
            )

        @app.post("/v1/action-challenges", status_code=201, response_model=ChallengeResponse,
                  response_model_by_alias=True)
        def create_action_challenge(body: ActionChallengeBody, request: Request) -> ChallengeResponse:
            who = principal(request)
            try:
                c = service.issue_action_challenge(body.device_id, who)
            except ChallengeCapacityExceeded:
                raise HTTPException(status_code=503, detail="try again later") from None
            if c is None:
                # Same answer for unknown, not-owned, pending and revoked devices.
                raise HTTPException(status_code=404, detail="device not enrolled")
            return _challenge_response(c)

        @app.post("/v1/actions/verify", response_model=ActionResponse, response_model_by_alias=True,
                  response_model_exclude_none=True)
        def verify_action(body: ActionBody, request: Request) -> ActionResponse:
            who = principal(request)
            signed_data = _b64(body.signed_data, "signedData")
            if len(signed_data) > MAX_SIGNED_DATA_BYTES:
                raise HTTPException(status_code=422, detail="signedData too large")
            result = service.verify_action(
                ActionRequest(
                    device_id=body.device_id,
                    challenge_id=body.challenge_id,
                    signed_data=signed_data,
                    signature=_b64(body.signature, "signature"),
                    key=body.key,
                    play_integrity_token=body.play_integrity_token,
                    client_ip=client_ip(request),
                ),
                principal=who,
            )
            return ActionResponse(
                decision=result.decision,
                decisionId=result.decision_id,
                action=SignedActionOut(type=result.action_type, params=result.params) if result.action_type else None,
                reasons=list(result.reasons) if expose_reasons else None,
                warnings=list(result.warnings) if expose_reasons else None,
                risk=_risk_out(result.risk) if expose_reasons else None,
            )

        @app.post("/v1/device-challenges", status_code=201, response_model=ChallengeResponse,
                  response_model_by_alias=True)
        def create_device_challenge(body: DeviceChallengeBody, request: Request) -> ChallengeResponse:
            """Run 17: single-use scan or key-rotation challenge for one active device the caller owns."""
            who = principal(request)
            try:
                c = service.issue_device_challenge(body.device_id, body.purpose, who)
            except ChallengeCapacityExceeded:
                raise HTTPException(status_code=503, detail="try again later") from None
            if c is None:
                raise HTTPException(status_code=404, detail="device not enrolled")
            return _challenge_response(c)

        @app.post("/v1/scans/verify", response_model=ScanResponse, response_model_by_alias=True,
                  response_model_exclude_none=True)
        def verify_scan(body: ScanBody, request: Request) -> ScanResponse:
            """Run 17: server-verified scan. Reports what was verified; never authorises a transaction."""
            who = principal(request)
            scan_data = _b64(body.scan_data, "scanData")
            if len(scan_data) > MAX_TRANSCRIPT_BYTES:
                raise HTTPException(status_code=422, detail="scanData too large")
            result = service.verify_scan(
                ScanRequest(
                    device_id=body.device_id,
                    challenge_id=body.challenge_id,
                    scan_data=scan_data,
                    signature=_b64(body.signature, "signature"),
                    fresh_chain=_decode_chain(body.fresh_attestation_chain) if body.fresh_attestation_chain else None,
                    play_integrity_token=body.play_integrity_token,
                ),
                principal=who,
            )
            coverage = dict(result.risk.coverage) if result.risk is not None and result.risk.coverage is not None else None
            return ScanResponse(
                decision=result.decision,
                decisionId=result.decision_id,
                verifiedAt=result.verified_at_ms,
                freshUntil=result.fresh_until_ms,
                policy=ScanPolicyOut(version=result.policy_version, digest=result.policy_digest,
                                     verifierRuleset=result.verifier_ruleset),
                evidence=result.evidence,
                coverage=coverage,
                history=ScanHistoryOut(**result.history) if result.history is not None else None,
                reasons=list(result.reasons) if expose_reasons else None,
                warnings=list(result.warnings) if expose_reasons else None,
                risk=_risk_out(result.risk) if expose_reasons else None,
            )

        @app.post("/v1/key-rotations", response_model=KeyRotationResponse, response_model_by_alias=True,
                  response_model_exclude_none=True)
        def rotate_key(body: KeyRotationBody, request: Request) -> KeyRotationResponse:
            """Run 17: the enrolled key authorises a new attested key. Only ALLOW changes the device."""
            who = principal(request)
            rotation_data = _b64(body.rotation_data, "rotationData")
            if len(rotation_data) > MAX_TRANSCRIPT_BYTES:
                raise HTTPException(status_code=422, detail="rotationData too large")
            result = service.rotate_key(
                KeyRotationRequest(
                    device_id=body.device_id,
                    challenge_id=body.challenge_id,
                    rotation_data=rotation_data,
                    old_key_signature=_b64(body.old_key_signature, "oldKeySignature"),
                    new_key_signature=_b64(body.new_key_signature, "newKeySignature"),
                    new_chain=_decode_chain(body.new_attestation_chain),
                    new_confirm_chain=_decode_chain(body.new_confirm_key_chain) if body.new_confirm_key_chain else None,
                ),
                principal=who,
            )
            return KeyRotationResponse(
                decision=result.decision,
                decisionId=result.decision_id,
                rotated=result.rotated,
                hasConfirmKey=result.has_confirm_key if result.rotated else None,
                reasons=list(result.reasons) if expose_reasons else None,
                warnings=list(result.warnings) if expose_reasons else None,
                risk=_risk_out(result.risk) if expose_reasons else None,
            )

        if gateway_token:
            @app.get("/v1/devices/{device_id}/history")
            def device_history(device_id: str, request: Request, limit: int = 20) -> dict:
                """Owner view of the device's attested history (no evidence JSON or backend reasons)."""
                history = service.device_history(device_id, principal(request), limit=max(1, min(limit, 50)))
                if history is None:
                    raise HTTPException(status_code=404, detail="device not found")
                return history

            @app.get("/v1/devices/{device_id}", response_model=DeviceStatusOut, response_model_by_alias=True)
            def device_status(device_id: str, request: Request) -> DeviceStatusOut:
                """Owner view of one device's lifecycle state (no evidence or backend reasons)."""
                status = service.device_status(device_id, principal(request))
                if status is None:
                    raise HTTPException(status_code=404, detail="device not found")
                return DeviceStatusOut(**status)

            @app.post("/v1/devices/{device_id}/step-up-completion", response_model=DeviceStatusOut,
                      response_model_by_alias=True)
            def complete_step_up(device_id: str, body: StepUpCompletionBody, request: Request) -> DeviceStatusOut:
                """The customer's backend reports that it verified the account owner (pending -> active)."""
                who = principal(request)
                outcome = service.complete_step_up(device_id, body.method, principal=who, actor="gateway")
                _step_up_http(outcome)
                return DeviceStatusOut(**service.device_status(device_id, who))

            @app.post("/v1/devices/{device_id}/revoke", status_code=204)
            def owner_revoke(device_id: str, body: OwnerRevokeBody, request: Request) -> None:
                if not service.revoke_owned_device(device_id, body.reason, principal(request)):
                    raise HTTPException(status_code=404, detail="device not found")


    if admin_token:
        def _require_admin(authorization: str) -> None:
            expected = f"Bearer {admin_token}"
            if not hmac.compare_digest(authorization.encode(), expected.encode()):
                raise HTTPException(status_code=401, detail="unauthorized")

        @app.get("/v1/admin/fleet")
        def fleet(hours: int = 24, limit: int = 10, authorization: str = Header(default="")) -> dict:
            """Fraud-team view: busiest network blocks, cohorts and attestation keys."""
            _require_admin(authorization)
            return service.fleet_summary(max(1, min(hours, 24 * 30)) * 3600, max(1, min(limit, 100)))

        @app.get("/v1/admin/devices/{device_id}")
        def device_detail(device_id: str, limit: int = 50, authorization: str = Header(default="")) -> dict:
            """Fraud-team view: device status, attested facts and recent decisions with risk factors."""
            _require_admin(authorization)
            detail = service.device_detail(device_id, limit=max(1, min(limit, 500)))
            if detail is None:
                raise HTTPException(status_code=404, detail="device not found")
            return detail

        @app.post("/v1/admin/devices/{device_id}/revoke", status_code=204)
        def revoke(device_id: str, body: RevokeBody, authorization: str = Header(default="")) -> None:
            _require_admin(authorization)
            if not service.revoke_device(device_id, body.reason):
                raise HTTPException(status_code=404, detail="device not found")

        @app.post("/v1/admin/devices/{device_id}/step-up-completion", status_code=204)
        def admin_complete_step_up(device_id: str, body: StepUpCompletionBody,
                                   authorization: str = Header(default="")) -> None:
            """Support-desk completion after verifying the customer out of band."""
            _require_admin(authorization)
            _step_up_http(service.complete_step_up(device_id, body.method, actor="admin"))

    return app
