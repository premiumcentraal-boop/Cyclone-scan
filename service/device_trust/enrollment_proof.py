"""Proof of possession binding the complete enrollment submission. Not proof of key co-location."""
import hashlib
import json
from .actions import verify_signature
from .play_integrity import b64url
from .strict_json import strict_loads

MAX_PROOF_BYTES = 32 * 1024
DOMAIN = b"device-trust/enroll-evidence/v1"
_FIELDS = {"v", "purpose", "challengeId", "nonce", "chainSha256",
           "confirmChainSha256", "device", "signals"}
_IDS = {"brand", "device", "product", "manufacturer", "model"}

def proof_request_hash(data: bytes) -> str:
    return b64url(hashlib.sha256(DOMAIN + data).digest())

def _digests(chain):
    return [hashlib.sha256(cert).hexdigest() for cert in chain] if chain else None

def _ids(raw):
    if not isinstance(raw, dict) or not set(raw) <= _IDS:
        raise ValueError("invalid reported fields")
    if any(not isinstance(v, str) or len(v) > 128 for v in raw.values()):
        raise ValueError("invalid reported values")
    return {k: v for k, v in raw.items() if v != ""}

def proof_data(challenge_id, nonce, chain, confirm_chain, device, signals):
    """Reference builder. The verifier checks exact signed bytes, not this serialization order."""
    return json.dumps({"v": 1, "purpose": "enrollment", "challengeId": challenge_id,
                       "nonce": b64url(nonce), "chainSha256": _digests(chain),
                       "confirmChainSha256": _digests(confirm_chain),
                       "device": _ids(device), "signals": signals},
                      separators=(",", ":"), allow_nan=False).encode("utf-8")

def validate_proof(data, signature, spki, challenge_id, nonce, chain, confirm_chain, device, signals):
    doc = strict_loads(data, MAX_PROOF_BYTES)
    if not isinstance(doc, dict) or set(doc) != _FIELDS:
        raise ValueError("unexpected enrollment proof fields")
    if type(doc["v"]) is not int or doc["v"] != 1 or doc["purpose"] != "enrollment":
        raise ValueError("wrong proof version or purpose")
    expected = strict_loads(proof_data(challenge_id, nonce, chain, confirm_chain, device, signals), MAX_PROOF_BYTES)
    doc["device"] = _ids(doc["device"])
    # JSON serialization distinguishes booleans from integers (unlike Python ==).
    if json.dumps(doc, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True, allow_nan=False):
        raise ValueError("proof does not describe this submission")
    if not isinstance(signature, bytes) or not 1 <= len(signature) <= 512 or not spki:
        raise ValueError("invalid proof signature encoding")
    if not verify_signature(spki, data, signature):
        raise ValueError("proof signature invalid")
    return proof_request_hash(data)
