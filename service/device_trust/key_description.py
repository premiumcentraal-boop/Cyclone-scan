"""Parser for the Android key attestation extension (KeyDescription).

Schema reference: https://source.android.com/docs/security/features/keystore/attestation

Only fields the trust decision uses are extracted. Serial, IMEI and MEID
attestation IDs are deliberately never decoded so they cannot leak into
results, logs or storage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .der import CLASS_CONTEXT, TAG_SEQUENCE, TAG_SET, DerError, Tlv, read_single

KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"


class SecurityLevel(IntEnum):
    SOFTWARE = 0
    TRUSTED_ENVIRONMENT = 1
    STRONG_BOX = 2


class VerifiedBootState(IntEnum):
    VERIFIED = 0
    SELF_SIGNED = 1
    UNVERIFIED = 2
    FAILED = 3


class KeyOrigin(IntEnum):
    GENERATED = 0
    DERIVED = 1
    IMPORTED = 2
    UNKNOWN = 3
    SECURELY_IMPORTED = 4


# AuthorizationList context tags (KeyMint Tag numbers masked to the low bits).
TAG_PURPOSE = 1
TAG_ALGORITHM = 2
TAG_ORIGIN = 702
TAG_ROOT_OF_TRUST = 704
TAG_OS_VERSION = 705
TAG_OS_PATCH_LEVEL = 706
TAG_ATTESTATION_APPLICATION_ID = 709
TAG_ID_BRAND = 710
TAG_ID_DEVICE = 711
TAG_ID_PRODUCT = 712
TAG_ID_MANUFACTURER = 716
TAG_ID_MODEL = 717
TAG_VENDOR_PATCH_LEVEL = 718
TAG_BOOT_PATCH_LEVEL = 719

_ID_TAGS = {
    TAG_ID_BRAND: "brand",
    TAG_ID_DEVICE: "device",
    TAG_ID_PRODUCT: "product",
    TAG_ID_MANUFACTURER: "manufacturer",
    TAG_ID_MODEL: "model",
}


@dataclass(frozen=True)
class RootOfTrust:
    verified_boot_key: bytes
    device_locked: bool
    verified_boot_state: VerifiedBootState
    verified_boot_hash: bytes | None


@dataclass(frozen=True)
class AttestationApplicationId:
    package_names: tuple[str, ...]
    signature_digests: tuple[bytes, ...]


@dataclass(frozen=True)
class AuthorizationList:
    purposes: frozenset[int] = frozenset()
    algorithm: int | None = None
    origin: KeyOrigin | None = None
    root_of_trust: RootOfTrust | None = None
    os_version: int | None = None
    os_patch_level: int | None = None
    vendor_patch_level: int | None = None
    boot_patch_level: int | None = None
    application_id: AttestationApplicationId | None = None
    attested_ids: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class KeyDescription:
    attestation_version: int
    attestation_security_level: SecurityLevel
    keymint_version: int
    keymint_security_level: SecurityLevel
    attestation_challenge: bytes
    software_enforced: AuthorizationList
    hardware_enforced: AuthorizationList


def _enum(enum_cls, value: int):
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise DerError(f"invalid {enum_cls.__name__} value {value}") from exc


def _explicit_inner(tlv: Tlv) -> Tlv:
    if not tlv.constructed:
        raise DerError(f"context tag [{tlv.tag}] must be explicitly tagged")
    return read_single(tlv.value)


def _parse_root_of_trust(tlv: Tlv) -> RootOfTrust:
    if not tlv.is_universal(TAG_SEQUENCE):
        raise DerError("RootOfTrust must be a SEQUENCE")
    items = tlv.children()
    if len(items) < 3:
        raise DerError("RootOfTrust too short")
    return RootOfTrust(
        verified_boot_key=items[0].as_bytes(),
        device_locked=items[1].as_bool(),
        verified_boot_state=_enum(VerifiedBootState, items[2].as_int()),
        verified_boot_hash=items[3].as_bytes() if len(items) > 3 else None,
    )


def _parse_application_id(raw: bytes) -> AttestationApplicationId:
    seq = read_single(raw)
    if not seq.is_universal(TAG_SEQUENCE):
        raise DerError("AttestationApplicationId must be a SEQUENCE")
    items = seq.children()
    if len(items) != 2 or not all(i.is_universal(TAG_SET) for i in items):
        raise DerError("AttestationApplicationId must hold two SETs")
    packages: list[str] = []
    for info in items[0].children():
        fields = info.children()
        if not fields:
            raise DerError("empty AttestationPackageInfo")
        packages.append(fields[0].as_bytes().decode("utf-8"))
    digests = tuple(d.as_bytes() for d in items[1].children())
    return AttestationApplicationId(tuple(packages), digests)


def _parse_authorization_list(tlv: Tlv) -> AuthorizationList:
    if not tlv.is_universal(TAG_SEQUENCE):
        raise DerError("AuthorizationList must be a SEQUENCE")
    values: dict = {"attested_ids": {}}
    seen: set[int] = set()
    for item in tlv.children():
        if item.cls != CLASS_CONTEXT:
            raise DerError("AuthorizationList entries must be context-tagged")
        if item.tag in seen:
            raise DerError(f"duplicate AuthorizationList tag [{item.tag}]")
        seen.add(item.tag)
        tag = item.tag
        if tag == TAG_PURPOSE:
            inner = _explicit_inner(item)
            values["purposes"] = frozenset(p.as_int() for p in inner.children())
        elif tag == TAG_ALGORITHM:
            values["algorithm"] = _explicit_inner(item).as_int()
        elif tag == TAG_ORIGIN:
            values["origin"] = _enum(KeyOrigin, _explicit_inner(item).as_int())
        elif tag == TAG_ROOT_OF_TRUST:
            values["root_of_trust"] = _parse_root_of_trust(_explicit_inner(item))
        elif tag == TAG_OS_VERSION:
            values["os_version"] = _explicit_inner(item).as_int()
        elif tag == TAG_OS_PATCH_LEVEL:
            values["os_patch_level"] = _explicit_inner(item).as_int()
        elif tag == TAG_VENDOR_PATCH_LEVEL:
            values["vendor_patch_level"] = _explicit_inner(item).as_int()
        elif tag == TAG_BOOT_PATCH_LEVEL:
            values["boot_patch_level"] = _explicit_inner(item).as_int()
        elif tag == TAG_ATTESTATION_APPLICATION_ID:
            values["application_id"] = _parse_application_id(_explicit_inner(item).as_bytes())
        elif tag in _ID_TAGS:
            raw = _explicit_inner(item).as_bytes()
            values["attested_ids"][_ID_TAGS[tag]] = raw.decode("utf-8", errors="strict")
        # Every other tag (including serial/IMEI/MEID) is intentionally skipped.
    return AuthorizationList(**values)


def parse_key_description(extension_value: bytes) -> KeyDescription:
    """Parse the DER value of the KeyDescription extension. Raises DerError."""
    seq = read_single(extension_value)
    if not seq.is_universal(TAG_SEQUENCE):
        raise DerError("KeyDescription must be a SEQUENCE")
    items = seq.children()
    if len(items) != 8:
        raise DerError(f"KeyDescription must have 8 fields, got {len(items)}")
    return KeyDescription(
        attestation_version=items[0].as_int(),
        attestation_security_level=_enum(SecurityLevel, items[1].as_int()),
        keymint_version=items[2].as_int(),
        keymint_security_level=_enum(SecurityLevel, items[3].as_int()),
        attestation_challenge=items[4].as_bytes(),
        # items[5] is uniqueId, unused and never retained.
        software_enforced=_parse_authorization_list(items[6]),
        hardware_enforced=_parse_authorization_list(items[7]),
    )
