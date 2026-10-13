"""Android hardware key attestation verifier.

Fails closed: any parsing error, unknown root, revoked certificate or stale
revocation list produces a failure reason. Checks implemented:

* chain signatures and issuer names, leaf -> root
* root public key is a trusted Google attestation root
* intermediates/root are inside their validity window
* no certificate in the chain is on Google's revocation list
* exactly one certificate (the leaf) carries the KeyDescription extension,
  which blocks the "attested key signs a forged leaf" attack
* challenge, security level, verified boot, bootloader lock, key origin,
  app package + signing certificate, OS patch age
* attested device IDs (brand/model/...) match what the app reports
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature

from . import reasons as R
from .der import DerError
from .key_description import (
    KEY_DESCRIPTION_OID,
    KeyDescription,
    KeyOrigin,
    VerifiedBootState,
    parse_key_description,
)
from .policy import TrustPolicy
from .revocation import RevocationList, RevocationUnavailable
from .roots import RootStore, spki_der

MAX_CHAIN_LENGTH = 10
_KEY_DESCRIPTION = x509.ObjectIdentifier(KEY_DESCRIPTION_OID)


@dataclass(frozen=True)
class AttestationEvidence:
    """Privacy-safe summary of what the hardware attested."""

    attestation_version: int
    attestation_security_level: str
    keymint_security_level: str
    device_locked: bool | None
    verified_boot_state: str | None
    verified_boot_key_sha256: str | None
    os_version: int | None
    os_patch_level: int | None
    vendor_patch_level: int | None
    boot_patch_level: int | None
    attested_ids: dict[str, str]
    mismatched_ids: tuple[str, ...]
    leaf_spki_sha256: str
    root_subject: str


@dataclass(frozen=True)
class AttestationResult:
    reasons: tuple[str, ...]
    evidence: AttestationEvidence | None = None
    # DER SubjectPublicKeyInfo of the attested key (used for device binding).
    leaf_public_key_spki: bytes | None = field(default=None, repr=False)

    @property
    def ok(self) -> bool:
        return not self.reasons


def patch_age_months(patch_level: int, now: datetime) -> int:
    """Months between a YYYYMM or YYYYMMDD patch level and ``now``."""
    if patch_level > 999999:
        patch_level //= 100
    year, month = divmod(patch_level, 100)
    if not 1 <= month <= 12 or year < 2000:
        raise ValueError(f"invalid patch level {patch_level}")
    return (now.year - year) * 12 + (now.month - month)


class AttestationVerifier:
    def __init__(self, policy: TrustPolicy, roots: RootStore, revocations: RevocationList):
        self._policy = policy
        self._roots = roots
        self._revocations = revocations

    def verify(
        self,
        chain_der: list[bytes],
        expected_challenge: bytes,
        reported_ids: dict[str, str] | None = None,
        now: datetime | None = None,
    ) -> AttestationResult:
        now = now or datetime.now(timezone.utc)

        # --- structure ------------------------------------------------------
        if not chain_der or len(chain_der) > MAX_CHAIN_LENGTH:
            return AttestationResult((R.CHAIN_MALFORMED,))
        try:
            certs = [x509.load_der_x509_certificate(c) for c in chain_der]
        except ValueError:
            return AttestationResult((R.CHAIN_MALFORMED,))
        if len(certs) < 2:
            return AttestationResult((R.CHAIN_MALFORMED,))

        ext_positions = [i for i, c in enumerate(certs) if _has_key_description(c)]
        if not ext_positions:
            return AttestationResult((R.ATTESTATION_EXTENSION_MISSING,))
        if ext_positions != [0]:
            return AttestationResult((R.ATTESTATION_EXTENSION_MISPLACED,))

        # --- cryptographic chain -------------------------------------------
        for child, issuer in zip(certs, certs[1:]):
            try:
                child.verify_directly_issued_by(issuer)
            except (ValueError, TypeError, InvalidSignature):
                return AttestationResult((R.CHAIN_SIGNATURE_INVALID,))
        root = self._roots.match(certs[-1])
        if root is None:
            return AttestationResult((R.ROOT_UNTRUSTED,))

        failures: list[str] = []
        skew = timedelta(seconds=self._policy.clock_skew_seconds)
        # Leaf validity is device-clock/keystore-defined and not meaningful.
        for cert in certs[1:]:
            if cert.not_valid_before_utc - skew > now or cert.not_valid_after_utc + skew < now:
                failures.append(R.CERT_EXPIRED)
                break

        try:
            if any(self._revocations.status(c.serial_number) for c in certs):
                failures.append(R.CERT_REVOKED)
        except RevocationUnavailable:
            failures.append(R.REVOCATION_UNAVAILABLE)

        # --- attestation contents ------------------------------------------
        try:
            ext_value = certs[0].extensions.get_extension_for_oid(_KEY_DESCRIPTION).value.value
            kd = parse_key_description(ext_value)
        except (DerError, UnicodeDecodeError, x509.ExtensionNotFound):
            return AttestationResult(tuple(failures + [R.ATTESTATION_EXTENSION_MALFORMED]))

        failures.extend(self._check_contents(kd, expected_challenge, now))
        mismatched = _compare_ids(kd.hardware_enforced.attested_ids, reported_ids or {})
        if mismatched:
            failures.append(R.DEVICE_ID_MISMATCH)

        leaf_spki = spki_der(certs[0])
        return AttestationResult(
            tuple(dict.fromkeys(failures)),
            _evidence(kd, mismatched, leaf_spki, root),
            leaf_spki,
        )

    def _check_contents(self, kd: KeyDescription, challenge: bytes, now: datetime) -> list[str]:
        p = self._policy
        out: list[str] = []
        if not hmac.compare_digest(kd.attestation_challenge, challenge):
            out.append(R.CHALLENGE_MISMATCH)
        if min(kd.attestation_security_level, kd.keymint_security_level) < p.min_security_level:
            out.append(R.SECURITY_LEVEL_TOO_LOW)

        hw = kd.hardware_enforced
        rot = hw.root_of_trust
        if rot is None:
            out.append(R.ROOT_OF_TRUST_MISSING)
        else:
            if not rot.device_locked:
                out.append(R.BOOTLOADER_UNLOCKED)
            if rot.verified_boot_state == VerifiedBootState.SELF_SIGNED:
                key_hash = hashlib.sha256(rot.verified_boot_key).hexdigest()
                if key_hash not in p.allowed_self_signed_boot_keys:
                    out.append(R.BOOT_STATE_SELF_SIGNED)
            elif rot.verified_boot_state != VerifiedBootState.VERIFIED:
                out.append(R.BOOT_STATE_UNVERIFIED)

        if hw.origin != KeyOrigin.GENERATED:
            out.append(R.KEY_NOT_HARDWARE_GENERATED)

        app_id = hw.application_id or kd.software_enforced.application_id
        if app_id is None:
            out.append(R.APP_ID_MISSING)
        else:
            if p.package_name not in app_id.package_names:
                out.append(R.PACKAGE_MISMATCH)
            digests = {d.hex() for d in app_id.signature_digests}
            if not digests or not digests <= p.signing_cert_sha256:
                out.append(R.SIGNING_CERT_MISMATCH)

        if hw.os_patch_level is None:
            out.append(R.OS_PATCH_UNKNOWN)
        else:
            try:
                if patch_age_months(hw.os_patch_level, now) > p.max_os_patch_age_months:
                    out.append(R.OS_PATCH_TOO_OLD)
            except ValueError:
                out.append(R.OS_PATCH_UNKNOWN)
        return out


def _has_key_description(cert: x509.Certificate) -> bool:
    try:
        cert.extensions.get_extension_for_oid(_KEY_DESCRIPTION)
        return True
    except x509.ExtensionNotFound:
        return False


def _compare_ids(attested: dict[str, str], reported: dict[str, str]) -> tuple[str, ...]:
    """Fields the hardware attested that differ from what the app reported.

    Missing reported values count as mismatches: a client that hides its Build
    fields should not get a free pass.
    """
    return tuple(
        sorted(name for name, value in attested.items() if (reported.get(name) or "").strip() != value.strip())
    )


def _evidence(kd: KeyDescription, mismatched, leaf_spki: bytes, root: x509.Certificate) -> AttestationEvidence:
    hw = kd.hardware_enforced
    rot = hw.root_of_trust
    return AttestationEvidence(
        attestation_version=kd.attestation_version,
        attestation_security_level=kd.attestation_security_level.name,
        keymint_security_level=kd.keymint_security_level.name,
        device_locked=rot.device_locked if rot else None,
        verified_boot_state=rot.verified_boot_state.name if rot else None,
        verified_boot_key_sha256=hashlib.sha256(rot.verified_boot_key).hexdigest() if rot else None,
        os_version=hw.os_version,
        os_patch_level=hw.os_patch_level,
        vendor_patch_level=hw.vendor_patch_level,
        boot_patch_level=hw.boot_patch_level,
        attested_ids=dict(hw.attested_ids),
        mismatched_ids=tuple(mismatched),
        leaf_spki_sha256=hashlib.sha256(leaf_spki).hexdigest(),
        root_subject=root.subject.rfc4514_string(),
    )
