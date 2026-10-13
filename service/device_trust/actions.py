"""Signed actions: parsing, binding and signature verification (Phase 2).

The app signs the *exact bytes* of a small JSON document with its enrolled
hardware key. The server parses those same bytes (so there is no
canonicalization step to get wrong), checks them against the server-issued
challenge, and hands the parsed action back to the backend, which executes
only what was signed ("what you see is what you sign").

    {"v": 1, "deviceId": "...", "challengeId": "...", "nonce": "<b64url>",
     "ts": <epoch ms>, "action": {"type": "payment", "params": {...}}}
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .play_integrity import b64url

ACTION_HASH_DOMAIN = b"device-trust/action/v1"
MAX_SIGNED_DATA_BYTES = 8 * 1024
_FIELDS = {"v", "deviceId", "challengeId", "nonce", "ts", "action"}
_ACTION_TYPE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

KEY_DEVICE = "device"
KEY_CONFIRM = "confirm"


class SignedDataError(ValueError):
    pass


@dataclass(frozen=True)
class SignedAction:
    device_id: str
    challenge_id: str
    nonce: str
    timestamp_ms: int
    action_type: str
    params: dict


def action_request_hash(signed_data: bytes) -> str:
    """Play Integrity requestHash for an action: base64url(SHA-256(domain || signedData)), unpadded."""
    return b64url(hashlib.sha256(ACTION_HASH_DOMAIN + signed_data).digest())


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            # Duplicate keys let two parsers disagree on what was signed.
            raise SignedDataError(f"duplicate key {key!r}")
        out[key] = value
    return out


def parse_signed_data(signed_data: bytes) -> SignedAction:
    if len(signed_data) > MAX_SIGNED_DATA_BYTES:
        raise SignedDataError("signed data too large")
    try:
        doc = json.loads(signed_data.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignedDataError("signed data is not UTF-8 JSON") from exc
    if not isinstance(doc, dict) or set(doc) != _FIELDS:
        raise SignedDataError("signed data must have exactly the documented fields")
    if type(doc["v"]) is not int or doc["v"] != 1:
        raise SignedDataError("unsupported signed data version")
    for key in ("deviceId", "challengeId", "nonce"):
        if not isinstance(doc[key], str) or not doc[key]:
            raise SignedDataError(f"{key} must be a non-empty string")
    if type(doc["ts"]) is not int:
        raise SignedDataError("ts must be an integer (epoch milliseconds)")
    action = doc["action"]
    if not isinstance(action, dict) or set(action) != {"type", "params"}:
        raise SignedDataError("action must have exactly 'type' and 'params'")
    if not isinstance(action["type"], str) or not _ACTION_TYPE.match(action["type"]):
        raise SignedDataError("invalid action type")
    if not isinstance(action["params"], dict):
        raise SignedDataError("action params must be an object")
    return SignedAction(
        device_id=doc["deviceId"],
        challenge_id=doc["challengeId"],
        nonce=doc["nonce"],
        timestamp_ms=doc["ts"],
        action_type=action["type"],
        params=action["params"],
    )


def verify_signature(public_key_spki: bytes, signed_data: bytes, signature: bytes) -> bool:
    """ECDSA P-256 / SHA-256 over the exact signed bytes (DER signature, as Android produces)."""
    try:
        key = load_der_public_key(public_key_spki)
    except ValueError:
        return False
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        return False
    try:
        key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True
