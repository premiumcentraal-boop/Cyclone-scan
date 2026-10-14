# Run 20 — authenticated enrollment evidence

Base: Run 13. SDK enrollment now signs a bounded, versioned transcript containing the server nonce,
challenge ID, ordered SHA-256 certificate-chain digests (including the optional confirm chain),
reported device fields and the exact signal values. Play Integrity binds its request hash to the
exact signed transcript through a distinct domain. The API accepts evidenceData/evidenceSignature.

Set require_bound_enrollment=true in production policy. Legacy submissions remain supported by
default for migration, with ENROLLMENT_LEGACY_UNBOUND recorded; this does not provide evidence binding.
Supplying a broken or partial proof always blocks, even in legacy mode. Invalid proofs do not
contribute trusted attestation-key history. Challenge consumption still happens before validation.

The signed JSON parser rejects duplicate keys at every depth, non-finite numbers, invalid Unicode
and excessive depth/size. No canonicalization occurs before signature verification.

Integration for Claude Runs 16–17: preserve these two additive request fields, the required-proof
policy and exact transcript bytes. Account/tenant/session authorization remains the authenticated
gateway/lifecycle's responsibility. This run does not add those state transitions.

Proof of possession is not proof of physical co-residency of the device and confirm keys, nor of
the UI the user saw. A biometric signature proves the configured authentication requirement was
satisfied, not that a compromised display showed the authentic action. No exactly-once external
payment execution is claimed; the consuming backend must use its own transactional/idempotent
execution boundary keyed to the approved action. Real-phone and live Google validation remain unverified.
