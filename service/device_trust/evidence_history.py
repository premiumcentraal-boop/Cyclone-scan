"""Compare authenticated measurements, never promote reported properties into signed facts.
No endpoint in this module accepts new keys as an existing device."""
import hashlib
from dataclasses import asdict

# Which classification/validity rules produced chain_type and the validity outcome, so a
# later reclassification can be told apart from a change in the device's evidence.
VERIFIER_RULESET = "run15-attestation-v1"

_FIELDS = ("attestation_security_level", "keymint_security_level", "device_locked",
           "verified_boot_state", "verified_boot_key_sha256", "verified_boot_hash",
           "os_version", "os_patch_level", "vendor_patch_level", "boot_patch_level",
           "chain_type", "leaf_spki_sha256")

def snapshot(evidence, public_key_spki):
    """Call only after verifier, enrollment proof and registration gates have succeeded."""
    if hashlib.sha256(public_key_spki).hexdigest() != evidence.leaf_spki_sha256:
        raise ValueError("snapshot key does not match enrolled key")
    raw = asdict(evidence)
    out = {"v": 1, **{field: raw.get(field) for field in _FIELDS}}
    out["attested_ids"] = {key: value for key, value in evidence.attested_ids.items()
                           if key in {"brand", "device", "product", "manufacturer", "model"}}
    # Verifier metadata (integration of Runs 15 and 22), additive within v1. Snapshots
    # written before this have neither key: treat that as unknown, never as False.
    out["verifier_ruleset"] = VERIFIER_RULESET
    out["legacy_validity_exemption"] = raw.get("legacy_validity_exemption")
    return out

def identity_sources(attested, reported):
    """For display/audit. Reported fields never fill the attested slot."""
    return {key: {"attested": attested.get(key), "reported": reported.get(key),
                  "source": "ATTESTED" if key in attested else "REPORTED_ONLY"}
            for key in ("brand", "device", "product", "manufacturer", "model")
            if key in attested or key in reported}

def _patch(value):
    if type(value) is not int or value < 200001:
        return None
    if value > 999999:
        year, rest = divmod(value, 10000)
        month, day = divmod(rest, 100)
        import datetime
        try: datetime.date(year, month, day)
        except ValueError: return None
        return year, month, day
    year, month = divmod(value, 100)
    return (year, month, None) if 2000 <= year <= 9999 and 1 <= month <= 12 else None

def compare(previous, current):
    if previous.get("v") != 1 or current.get("v") != 1:
        raise ValueError("unsupported snapshot version")
    if previous.get("leaf_spki_sha256") != current.get("leaf_spki_sha256"):
        return [{"code": "KEY_CONTINUITY_UNVERIFIED", "level": "REVIEW", "field": "leaf_spki_sha256"}]
    out = []
    for key in ("device_locked", "verified_boot_state", "verified_boot_key_sha256"):
        old, new = previous.get(key), current.get(key)
        if old is not None and new is not None and old != new:
            out.append({"code": "BOOT_EVIDENCE_CHANGED", "level": "REVIEW", "field": key})
    for key in ("brand", "device", "product", "manufacturer", "model"):
        old, new = (previous.get("attested_ids") or {}).get(key), (current.get("attested_ids") or {}).get(key)
        if old and new and old != new:
            out.append({"code": "ATTESTED_IDENTITY_CHANGED", "level": "REVIEW", "field": key})
    for key in ("os_patch_level", "vendor_patch_level", "boot_patch_level"):
        old, new = _patch(previous.get(key)), _patch(current.get(key))
        if old is None or new is None:
            out.append({"code": "PATCH_COMPARISON_UNAVAILABLE", "level": "INFO", "field": key})
        elif new[:2] < old[:2] or (new[:2] == old[:2] and new[2] is not None and old[2] is not None and new[2] < old[2]):
            out.append({"code": "PATCH_REGRESSION", "level": "REVIEW", "field": key})
    old_hash, new_hash = previous.get("verified_boot_hash"), current.get("verified_boot_hash")
    if old_hash and new_hash and old_hash != new_hash:
        out.append({"code": "BOOT_IMAGE_CHANGED", "level": "INFO", "field": "verified_boot_hash"})
    return out
