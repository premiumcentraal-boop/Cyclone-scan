"""Minimal strict DER reader for the Android KeyDescription extension.

Only the subset of X.690 that Android key attestation uses is supported:
definite lengths, single- and multi-byte tag numbers, primitive and
constructed encodings. Anything malformed raises :class:`DerError` so callers
fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass

CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2
CLASS_PRIVATE = 3

TAG_BOOLEAN = 1
TAG_INTEGER = 2
TAG_OCTET_STRING = 4
TAG_NULL = 5
TAG_ENUMERATED = 10
TAG_SEQUENCE = 16
TAG_SET = 17


class DerError(ValueError):
    """Raised for any malformed or unexpected DER input."""


@dataclass(frozen=True)
class Tlv:
    cls: int
    constructed: bool
    tag: int
    value: bytes

    def is_universal(self, tag: int) -> bool:
        return self.cls == CLASS_UNIVERSAL and self.tag == tag

    def children(self) -> list["Tlv"]:
        if not self.constructed:
            raise DerError("primitive value has no children")
        return read_all(self.value)

    def as_int(self) -> int:
        if self.constructed or self.cls != CLASS_UNIVERSAL or self.tag not in (TAG_INTEGER, TAG_ENUMERATED):
            raise DerError(f"expected INTEGER/ENUMERATED, got class={self.cls} tag={self.tag}")
        if not self.value:
            raise DerError("empty INTEGER")
        return int.from_bytes(self.value, "big", signed=True)

    def as_bool(self) -> bool:
        if self.constructed or not self.is_universal(TAG_BOOLEAN) or self.value not in (b"\x00", b"\xff"):
            # DER allows only 0x00 / 0xFF; anything else signals a tampered encoding.
            raise DerError("expected DER BOOLEAN")
        return self.value == b"\xff"

    def as_bytes(self) -> bytes:
        if self.constructed or not self.is_universal(TAG_OCTET_STRING):
            raise DerError("expected OCTET STRING")
        return self.value


def _read_one(data: bytes, offset: int) -> tuple[Tlv, int]:
    end = len(data)
    if offset >= end:
        raise DerError("unexpected end of data")
    first = data[offset]
    offset += 1
    cls = first >> 6
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag == 0x1F:
        tag = 0
        for _ in range(5):
            if offset >= end:
                raise DerError("truncated tag")
            b = data[offset]
            offset += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
        else:
            raise DerError("tag number too large")
    if offset >= end:
        raise DerError("truncated length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise DerError("unsupported length encoding")
        if offset + n > end:
            raise DerError("truncated length")
        length = int.from_bytes(data[offset : offset + n], "big")
        offset += n
    if offset + length > end:
        raise DerError("value overruns buffer")
    return Tlv(cls, constructed, tag, data[offset : offset + length]), offset + length


def read_all(data: bytes) -> list[Tlv]:
    out: list[Tlv] = []
    offset = 0
    while offset < len(data):
        tlv, offset = _read_one(data, offset)
        out.append(tlv)
    return out


def read_single(data: bytes) -> Tlv:
    tlv, offset = _read_one(data, 0)
    if offset != len(data):
        raise DerError("trailing data after top-level value")
    return tlv
