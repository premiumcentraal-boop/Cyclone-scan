"""Builds synthetic Android attestation chains for tests.

The chain mirrors a real device: test root CA -> intermediate (batch) CA ->
leaf for the app key, with the KeyDescription extension on the leaf.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from device_trust.key_description import KEY_DESCRIPTION_OID

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
PACKAGE = "com.example.bank"
SIGNING_DIGEST = hashlib.sha256(b"example-signing-cert").digest()
BOOT_KEY = hashlib.sha256(b"oem-verified-boot-key").digest()
DEVICE_IDS = {
    "brand": "google",
    "device": "shiba",
    "product": "shiba",
    "manufacturer": "Google",
    "model": "Pixel 8",
}


# --- tiny DER encoder -------------------------------------------------------

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag_byte: int, value: bytes) -> bytes:
    return bytes([tag_byte]) + _len(len(value)) + value


def integer(v: int) -> bytes:
    length = max(1, (v.bit_length() + 8) // 8)
    return tlv(0x02, v.to_bytes(length, "big", signed=True))


def enumerated(v: int) -> bytes:
    return tlv(0x0A, integer(v)[2:])


def boolean(v: bool) -> bytes:
    return tlv(0x01, b"\xff" if v else b"\x00")


def octets(v: bytes) -> bytes:
    return tlv(0x04, v)


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))


def explicit(tag: int, inner: bytes) -> bytes:
    """Context-specific, constructed, explicit tag (supports high tag numbers)."""
    if tag < 31:
        head = bytes([0xA0 | tag])
    else:
        groups = []
        t = tag
        while True:
            groups.insert(0, t & 0x7F)
            t >>= 7
            if not t:
                break
        head = bytes([0xBF]) + bytes([g | 0x80 for g in groups[:-1]] + [groups[-1]])
    return head + _len(len(inner)) + inner


# --- KeyDescription ----------------------------------------------------------

@dataclass
class KD:
    challenge: bytes = b"challenge"
    attestation_version: int = 300
    security_level: int = 1
    keymint_security_level: int = 1
    device_locked: bool = True
    boot_state: int = 0
    boot_key: bytes = BOOT_KEY
    origin: int = 0
    os_version: int = 160000
    os_patch_level: int = 202609
    vendor_patch_level: int | None = 20260905
    package: str = PACKAGE
    signing_digests: list[bytes] = field(default_factory=lambda: [SIGNING_DIGEST])
    attested_ids: dict[str, str] = field(default_factory=lambda: dict(DEVICE_IDS))
    include_root_of_trust: bool = True
    include_app_id: bool = True
    serial: str | None = "SERIAL123"
    imei: str | None = "359999999999999"

    def encode(self) -> bytes:
        app_id = seq(
            set_of(seq(octets(self.package.encode()), integer(1))),
            set_of(*(octets(d) for d in self.signing_digests)),
        )
        sw = [explicit(701, integer(1_760_000_000_000))]
        if self.include_app_id:
            sw.append(explicit(709, octets(app_id)))

        hw: list[tuple[int, bytes]] = [
            (1, set_of(integer(2), integer(3))),
            (2, integer(3)),
            (702, integer(self.origin)),
            (705, integer(self.os_version)),
            (706, integer(self.os_patch_level)),
        ]
        if self.include_root_of_trust:
            hw.append((704, seq(octets(self.boot_key), boolean(self.device_locked),
                                enumerated(self.boot_state), octets(b"\x11" * 32))))
        id_tags = {"brand": 710, "device": 711, "product": 712, "manufacturer": 716, "model": 717}
        for name, value in self.attested_ids.items():
            hw.append((id_tags[name], octets(value.encode())))
        if self.serial is not None:
            hw.append((713, octets(self.serial.encode())))
        if self.imei is not None:
            hw.append((714, octets(self.imei.encode())))
        if self.vendor_patch_level is not None:
            hw.append((718, integer(self.vendor_patch_level)))
        hw_encoded = [explicit(tag, inner) for tag, inner in sorted(hw, key=lambda t: t[0])]

        return seq(
            integer(self.attestation_version),
            enumerated(self.security_level),
            integer(self.attestation_version),
            enumerated(self.keymint_security_level),
            octets(self.challenge),
            octets(b""),
            seq(*sw),
            seq(*hw_encoded),
        )


# --- certificates -----------------------------------------------------------

def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, public_key, signing_key, *, ca: bool, serial: int, not_before, not_after,
          extensions=()) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    for ext in extensions:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(signing_key, hashes.SHA256())


def kd_extension(kd_der: bytes) -> x509.UnrecognizedExtension:
    return x509.UnrecognizedExtension(x509.ObjectIdentifier(KEY_DESCRIPTION_OID), kd_der)


@dataclass
class Pki:
    root_key: ec.EllipticCurvePrivateKey
    root: x509.Certificate
    inter_key: ec.EllipticCurvePrivateKey
    inter: x509.Certificate


def make_pki(*, inter_serial: int = 0x1F4363F4ACEF, inter_not_after: datetime | None = None,
             root_cn: str = "Test Attestation Root") -> Pki:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _cert(_name(root_cn), _name(root_cn), root_key.public_key(), root_key, ca=True, serial=1,
                 not_before=NOW - timedelta(days=3650), not_after=NOW + timedelta(days=3650))
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter = _cert(_name("Test Batch Key"), root.subject, inter_key.public_key(), root_key, ca=True,
                  serial=inter_serial, not_before=NOW - timedelta(days=365),
                  not_after=inter_not_after or NOW + timedelta(days=365))
    return Pki(root_key, root, inter_key, inter)


def make_leaf(pki: Pki, kd: KD | bytes | None, *, leaf_key=None, serial: int = 1) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    leaf_key = leaf_key or ec.generate_private_key(ec.SECP256R1())
    exts = []
    if kd is not None:
        exts.append(kd_extension(kd if isinstance(kd, bytes) else kd.encode()))
    # Real leaves often have validity copied from key params; use something odd on purpose.
    leaf = _cert(_name("Android Keystore Key"), pki.inter.subject, leaf_key.public_key(), pki.inter_key,
                 ca=False, serial=serial, not_before=datetime(1970, 1, 1, tzinfo=timezone.utc),
                 not_after=datetime(2048, 1, 1, tzinfo=timezone.utc), extensions=exts)
    return leaf, leaf_key


def chain_der(*certs: x509.Certificate) -> list[bytes]:
    from cryptography.hazmat.primitives.serialization import Encoding

    return [c.public_bytes(Encoding.DER) for c in certs]


def make_chain(kd: KD | None = None, pki: Pki | None = None) -> tuple[list[bytes], Pki, ec.EllipticCurvePrivateKey]:
    pki = pki or make_pki()
    leaf, leaf_key = make_leaf(pki, kd or KD())
    return chain_der(leaf, pki.inter, pki.root), pki, leaf_key
