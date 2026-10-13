"""Trusted attestation roots.

Roots are matched by SubjectPublicKeyInfo rather than by whole certificate,
because Google has re-issued its RSA root with the same key. The bundled set
comes from https://android.googleapis.com/attestation/root; refresh it with
``device-trust refresh-roots``.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

GOOGLE_ROOTS_URL = "https://android.googleapis.com/attestation/root"


def spki_der(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


class RootStore:
    def __init__(self, certificates: list[x509.Certificate]):
        if not certificates:
            raise ValueError("root store must not be empty")
        self._by_spki = {spki_der(c): c for c in certificates}

    def match(self, cert: x509.Certificate) -> x509.Certificate | None:
        """Return the trusted root with the same public key, if any."""
        return self._by_spki.get(spki_der(cert))

    def __len__(self) -> int:
        return len(self._by_spki)

    @classmethod
    def from_pem_list(cls, pems: list[str]) -> "RootStore":
        return cls([x509.load_pem_x509_certificate(p.encode("ascii")) for p in pems])

    @classmethod
    def from_json_file(cls, path: str | Path) -> "RootStore":
        return cls.from_pem_list(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def bundled_google(cls) -> "RootStore":
        text = resources.files("device_trust").joinpath("trust_anchors/google_roots.json").read_text("utf-8")
        return cls.from_pem_list(json.loads(text))
