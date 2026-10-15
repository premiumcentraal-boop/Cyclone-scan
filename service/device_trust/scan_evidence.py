"""Signed scan and key-rotation transcripts (Run 17).

The enrolled device key signs the exact bytes of one of these documents. The
server parses those bytes with the strict bounded parser and never
re-serializes before verifying. Each purpose has its own domain, so a
signature or Play Integrity token made for enrollment, an action, a scan or a
key rotation cannot be replayed as another.

    scan:          {"v":1,"purpose":"scan","deviceId","challengeId","nonce","ts",
                    "freshChainSha256":[hex,...]|null,"device":{...},"signals":{...}|null}
    key-rotation:  {"v":1,"purpose":"key-rotation","deviceId","challengeId","nonce","ts",
                    "newChainSha256":[hex,...],"newConfirmChainSha256":[hex,...]|null,"device":{...}}

Signing proves the holder of the enrolled key authorised this evidence. It
does not prove that a fresh or new key lives on the same physical phone.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from .enrollment_proof import _digests, _ids
from .play_integrity import b64url
from .strict_json import strict_loads

SCAN_DOMAIN = b"device-trust/scan-evidence/v1"
ROTATION_DOMAIN = b"device-trust/key-rotation/v1"
MAX_TRANSCRIPT_BYTES = 32 * 1024

PURPOSE_SCAN = "scan"
PURPOSE_KEY_ROTATION = "key-rotation"
PURPOSES = (PURPOSE_SCAN, PURPOSE_KEY_ROTATION)

_COMMON = {"v", "purpose", "deviceId", "challengeId", "nonce", "ts", "device"}
_FIELDS = {
    PURPOSE_SCAN: _COMMON | {"freshChainSha256", "signals"},
    PURPOSE_KEY_ROTATION: _COMMON | {"newChainSha256", "newConfirmChainSha256"},
}
_DOMAINS = {PURPOSE_SCAN: SCAN_DOMAIN, PURPOSE_KEY_ROTATION: ROTATION_DOMAIN}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_CHAIN_CERTS = 10


@dataclass(frozen=True)
class Transcript:
    purpose: str
    device_id: str
    challenge_id: str
    nonce: str
    timestamp_ms: int
    device: dict
    # scan: fresh chain digests (None = no fresh chain); rotation: new device-key chain.
    chain_sha256: list | None
    # rotation only: new confirm-key chain digests (None = no confirm key).
    confirm_chain_sha256: list | None = None
    # scan only: the raw client signal report (None = not reported).
    signals: object = None


def challenge_binding(purpose: str, device_id: str) -> str:
    """Challenge-store binding: distinct from enrollment ('enroll:...') and action (bare device ID)."""
    if purpose not in PURPOSES:
        raise ValueError("unknown device challenge purpose")
    return f"{purpose}:{device_id}"


def request_hash(purpose: str, data: bytes) -> str:
    """Play Integrity requestHash: unpadded base64url(SHA-256(domain || exact transcript bytes))."""
    return b64url(hashlib.sha256(_DOMAINS[purpose] + data).digest())


def chain_digests(chain: list[bytes] | None) -> list[str] | None:
    return _digests(chain)


def _digest_list(value, *, nullable: bool):
    if value is None and nullable:
        return None
    if (not isinstance(value, list) or not 1 <= len(value) <= MAX_CHAIN_CERTS
            or any(not isinstance(d, str) or not _HEX64.match(d) for d in value)):
        raise ValueError("invalid chain digest list")
    return list(value)


def parse(data: bytes, purpose: str) -> Transcript:
    """Strictly parse one transcript of the expected purpose; raises ValueError."""
    doc = strict_loads(data, MAX_TRANSCRIPT_BYTES)
    if not isinstance(doc, dict) or set(doc) != _FIELDS[purpose]:
        raise ValueError("unexpected transcript fields")
    if type(doc["v"]) is not int or doc["v"] != 1 or doc["purpose"] != purpose:
        raise ValueError("wrong transcript version or purpose")
    for key in ("deviceId", "challengeId", "nonce"):
        if not isinstance(doc[key], str) or not 1 <= len(doc[key]) <= 128:
            raise ValueError(f"{key} must be a non-empty string")
    if type(doc["ts"]) is not int or doc["ts"] < 0:
        raise ValueError("ts must be an integer (epoch milliseconds)")
    device = _ids(doc["device"])
    if purpose == PURPOSE_SCAN:
        if doc["signals"] is not None and not isinstance(doc["signals"], dict):
            raise ValueError("signals must be an object or null")
        return Transcript(purpose, doc["deviceId"], doc["challengeId"], doc["nonce"], doc["ts"], device,
                          _digest_list(doc["freshChainSha256"], nullable=True), signals=doc["signals"])
    return Transcript(purpose, doc["deviceId"], doc["challengeId"], doc["nonce"], doc["ts"], device,
                      _digest_list(doc["newChainSha256"], nullable=False),
                      _digest_list(doc["newConfirmChainSha256"], nullable=True))


def _encode(doc: dict) -> bytes:
    return json.dumps(doc, separators=(",", ":"), allow_nan=False).encode("utf-8")


def scan_data(device_id, challenge_id, nonce: bytes, ts: int, fresh_chain, device, signals) -> bytes:
    """Reference builder (tests, fixtures). The verifier checks exact bytes, not this order."""
    return _encode({"v": 1, "purpose": PURPOSE_SCAN, "deviceId": device_id, "challengeId": challenge_id,
                    "nonce": b64url(nonce), "ts": ts, "freshChainSha256": chain_digests(fresh_chain),
                    "device": _ids(device), "signals": signals})


def rotation_data(device_id, challenge_id, nonce: bytes, ts: int, new_chain, new_confirm_chain, device) -> bytes:
    """Reference builder (tests, fixtures)."""
    return _encode({"v": 1, "purpose": PURPOSE_KEY_ROTATION, "deviceId": device_id,
                    "challengeId": challenge_id, "nonce": b64url(nonce), "ts": ts,
                    "newChainSha256": chain_digests(new_chain),
                    "newConfirmChainSha256": chain_digests(new_confirm_chain), "device": _ids(device)})
