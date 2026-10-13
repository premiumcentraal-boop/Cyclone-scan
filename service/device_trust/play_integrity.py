"""Play Integrity API (standard requests) decoding and verdict evaluation.

Standard-request tokens can only be decrypted by Google, so decoding calls
``playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken`` with a
service-account OAuth token. That API is free within the Play Integrity quota.

The request is bound to the enrollment by ``requestHash`` (see
:func:`enrollment_request_hash`), so a token captured from another device or
another challenge cannot be replayed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from . import reasons as R
from .policy import TrustPolicy

PLAY_INTEGRITY_SCOPE = "https://www.googleapis.com/auth/playintegrity"
DECODE_URL = "https://playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken"
ENROLL_HASH_DOMAIN = b"device-trust/enroll/v1"


class DecodeError(RuntimeError):
    """The token could not be decoded (network, auth or invalid token)."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def enrollment_request_hash(nonce: bytes, leaf_spki_der: bytes) -> str:
    """requestHash the app must pass to Play Integrity during enrollment.

    base64url(SHA-256("device-trust/enroll/v1" || nonce || attested key SPKI DER)), unpadded.
    """
    return b64url(hashlib.sha256(ENROLL_HASH_DOMAIN + nonce + leaf_spki_der).digest())


class IntegrityTokenDecoder(Protocol):
    def decode(self, package_name: str, token: str) -> dict: ...


HttpPost = Callable[[str, bytes, dict[str, str]], bytes]


def _http_post(url: str, body: bytes, headers: dict[str, str]) -> bytes:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - fixed https URLs
        return resp.read()


class GoogleApiDecoder:
    """Decodes tokens through Google's API using a service-account key file."""

    def __init__(self, service_account: dict, *, post: HttpPost = _http_post, clock: Callable[[], float] = time.time):
        for key in ("client_email", "private_key", "token_uri"):
            if not service_account.get(key):
                raise ValueError(f"service account JSON is missing {key!r}")
        self._email = service_account["client_email"]
        self._token_uri = service_account["token_uri"]
        self._key = serialization.load_pem_private_key(service_account["private_key"].encode(), password=None)
        self._post = post
        self._clock = clock
        self._lock = threading.Lock()
        self._access_token: str | None = None
        self._expires_at = 0.0

    @classmethod
    def from_file(cls, path: str | Path, **kwargs) -> "GoogleApiDecoder":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")), **kwargs)

    def _assertion(self, now: int) -> str:
        header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        claims = b64url(
            json.dumps(
                {
                    "iss": self._email,
                    "scope": PLAY_INTEGRITY_SCOPE,
                    "aud": self._token_uri,
                    "iat": now,
                    "exp": now + 3600,
                }
            ).encode()
        )
        signing_input = f"{header}.{claims}".encode()
        signature = self._key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{claims}.{b64url(signature)}"

    def _token(self) -> str:
        with self._lock:
            now = self._clock()
            if self._access_token and now < self._expires_at - 60:
                return self._access_token
            body = urllib.parse.urlencode(
                {
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": self._assertion(int(now)),
                }
            ).encode()
            raw = self._post(self._token_uri, body, {"Content-Type": "application/x-www-form-urlencoded"})
            data = json.loads(raw)
            self._access_token = data["access_token"]
            self._expires_at = now + int(data.get("expires_in", 3600))
            return self._access_token

    def decode(self, package_name: str, token: str) -> dict:
        try:
            url = DECODE_URL.format(package=urllib.parse.quote(package_name, safe=""))
            raw = self._post(
                url,
                json.dumps({"integrity_token": token}).encode(),
                {"Content-Type": "application/json", "Authorization": f"Bearer {self._token()}"},
            )
            payload = json.loads(raw)["tokenPayloadExternal"]
        except Exception as exc:  # network, auth, JSON or missing payload
            raise DecodeError("could not decode Play Integrity token") from exc
        if not isinstance(payload, dict):
            raise DecodeError("tokenPayloadExternal is not an object")
        return payload


@dataclass(frozen=True)
class PlayIntegrityResult:
    reasons: tuple[str, ...]
    # Non-identifying verdict signals kept for later risk scoring (Phase 3).
    signals: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.reasons


def evaluate_payload(
    payload: dict,
    policy: TrustPolicy,
    expected_request_hash: str,
    now_ms: int | None = None,
) -> PlayIntegrityResult:
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
    out: list[str] = []

    req = payload.get("requestDetails") or {}
    if req.get("requestPackageName") != policy.package_name or not hmac.compare_digest(
        str(req.get("requestHash", "")).encode(), expected_request_hash.encode()
    ):
        out.append(R.PLAY_INTEGRITY_REQUEST_MISMATCH)
    try:
        ts = int(req.get("timestampMillis"))
    except (TypeError, ValueError):
        ts = None
    skew_ms = policy.clock_skew_seconds * 1000
    if ts is None or ts > now_ms + skew_ms or now_ms - ts > policy.play_integrity_max_age_seconds * 1000:
        out.append(R.PLAY_INTEGRITY_STALE)

    app = payload.get("appIntegrity") or {}
    app_verdict = app.get("appRecognitionVerdict")
    if policy.require_play_recognized and app_verdict != "PLAY_RECOGNIZED":
        out.append(R.PLAY_APP_NOT_RECOGNIZED)
    if app_verdict not in (None, "UNEVALUATED"):
        if app.get("packageName") != policy.package_name:
            out.append(R.PLAY_APP_NOT_RECOGNIZED)
        try:
            digests = {b64url_decode(d).hex() for d in app.get("certificateSha256Digest") or ()}
        except (ValueError, TypeError):
            digests = set()
        if not digests or not digests <= policy.signing_cert_sha256:
            out.append(R.SIGNING_CERT_MISMATCH)

    device = payload.get("deviceIntegrity") or {}
    verdicts = list(device.get("deviceRecognitionVerdict") or ())
    if "MEETS_DEVICE_INTEGRITY" not in verdicts and "MEETS_STRONG_INTEGRITY" not in verdicts:
        out.append(R.PLAY_DEVICE_INTEGRITY_FAILED)

    env = payload.get("environmentDetails") or {}
    signals = {
        "device_recognition": sorted(verdicts),
        "app_recognition": app_verdict,
        "app_licensing": (payload.get("accountDetails") or {}).get("appLicensingVerdict"),
        "play_protect": env.get("playProtectVerdict"),
        "app_access_risk": sorted((env.get("appAccessRiskVerdict") or {}).get("appsDetected") or ()),
        "device_activity_level": (device.get("recentDeviceActivity") or {}).get("deviceActivityLevel"),
    }
    return PlayIntegrityResult(tuple(dict.fromkeys(out)), signals)
