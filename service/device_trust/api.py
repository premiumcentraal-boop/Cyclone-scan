"""HTTP API (FastAPI).

Deploy behind the bank backend / API gateway: the app should reach these
endpoints only through an authenticated session. By default responses do not
include failure reasons, so attackers cannot use the API as a bypass oracle;
operators look reasons up in the decision log by ``decisionId``.
"""

from __future__ import annotations

import base64
import binascii

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .challenges import ChallengeCapacityExceeded
from .play_integrity import b64url
from .service import DeviceTrustService, EnrollmentRequest

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


class EnrollmentResponse(_Model):
    decision: str
    decision_id: str = Field(alias="decisionId")
    device_id: str | None = Field(default=None, alias="deviceId")
    reasons: list[str] | None = None
    warnings: list[str] | None = None


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


def create_app(service: DeviceTrustService, *, expose_reasons: bool = False) -> FastAPI:
    app = FastAPI(title="Device Trust Service", version="0.1.0")

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/v1/challenges", status_code=201, response_model=ChallengeResponse, response_model_by_alias=True)
    def create_challenge() -> ChallengeResponse:
        try:
            c = service.issue_challenge()
        except ChallengeCapacityExceeded:
            raise HTTPException(status_code=503, detail="try again later") from None
        return ChallengeResponse(challengeId=c.challenge_id, nonce=b64url(c.nonce), expiresAt=int(c.expires_at))

    @app.post("/v1/enrollments", response_model=EnrollmentResponse, response_model_by_alias=True,
              response_model_exclude_none=True)
    def enroll(body: EnrollmentBody) -> EnrollmentResponse:
        reported = body.device.model_dump()
        req = EnrollmentRequest(
            challenge_id=body.challenge_id,
            attestation_chain=_decode_chain(body.attestation_chain),
            reported_ids={k: reported[k] for k in ID_FIELDS if reported[k]},
            play_integrity_token=body.play_integrity_token,
        )
        result = service.enroll(req)
        return EnrollmentResponse(
            decision=result.decision,
            decisionId=result.decision_id,
            deviceId=result.device_id,
            reasons=list(result.reasons) if expose_reasons else None,
            warnings=list(result.warnings) if expose_reasons else None,
        )

    return app
