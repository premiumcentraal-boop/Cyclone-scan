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
from pydantic import BaseModel, ConfigDict, Field

from .actions import MAX_SIGNED_DATA_BYTES
from .challenges import Challenge, ChallengeCapacityExceeded
from .play_integrity import b64url
from .service import ActionRequest, DeviceTrustService, EnrollmentRequest

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
) -> FastAPI:
    """Build the API. ``admin_token`` enables the admin endpoints; without it they are absent.

    ``trust_forwarded_for``: take the client IP from the first X-Forwarded-For
    entry. Enable only behind a proxy that sets it, otherwise callers can forge it.
    """

    def client_ip(request: Request) -> str | None:
        if trust_forwarded_for:
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded.strip():
                return forwarded.split(",")[0].strip()
        return request.client.host if request.client else None

    app = FastAPI(title="Device Trust Service", version="0.5.0")

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/v1/challenges", status_code=201, response_model=ChallengeResponse, response_model_by_alias=True)
    def create_challenge() -> ChallengeResponse:
        try:
            c = service.issue_challenge()
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
            client_ip=client_ip(request),
        )
        result = service.enroll(req)
        return EnrollmentResponse(
            decision=result.decision,
            decisionId=result.decision_id,
            deviceId=result.device_id,
            reasons=list(result.reasons) if expose_reasons else None,
            warnings=list(result.warnings) if expose_reasons else None,
            risk=_risk_out(result.risk) if expose_reasons else None,
        )

    @app.post("/v1/action-challenges", status_code=201, response_model=ChallengeResponse,
              response_model_by_alias=True)
    def create_action_challenge(body: ActionChallengeBody) -> ChallengeResponse:
        try:
            c = service.issue_action_challenge(body.device_id)
        except ChallengeCapacityExceeded:
            raise HTTPException(status_code=503, detail="try again later") from None
        if c is None:
            # Same answer for unknown and revoked devices.
            raise HTTPException(status_code=404, detail="device not enrolled")
        return _challenge_response(c)

    @app.post("/v1/actions/verify", response_model=ActionResponse, response_model_by_alias=True,
              response_model_exclude_none=True)
    def verify_action(body: ActionBody, request: Request) -> ActionResponse:
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
            )
        )
        return ActionResponse(
            decision=result.decision,
            decisionId=result.decision_id,
            action=SignedActionOut(type=result.action_type, params=result.params) if result.action_type else None,
            reasons=list(result.reasons) if expose_reasons else None,
            warnings=list(result.warnings) if expose_reasons else None,
            risk=_risk_out(result.risk) if expose_reasons else None,
        )

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

    return app
