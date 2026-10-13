# Device Trust Service — Phase 1

Server-side verification that an Android device is genuine, unmodified and
running your real app, before it is allowed to enroll for banking.

**The phone collects evidence; this service decides.** Client-side checks can
be hooked; hardware-signed evidence cannot be forged without a leaked key,
and leaked keys are on Google's revocation list, which this service enforces.

Phase 1 = enrollment with **hard-fail gates** (ALLOW / BLOCK). Device binding
for per-action signatures (Phase 2), client RASP signals and risk scoring
(Phase 3) and policy tuning (Phase 4) build on this.

## What is verified

| Check | Source | Reason code on failure |
|---|---|---|
| Single-use, short-lived challenge | server | `CHALLENGE_UNKNOWN`, `CHALLENGE_MISMATCH` |
| Chain signatures, leaf → root | key attestation | `CHAIN_SIGNATURE_INVALID`, `CHAIN_MALFORMED` |
| Root key is a Google hardware attestation root (RSA + 2025 EC "Key Attestation CA1") | bundled `trust_anchors/google_roots.json` | `ROOT_UNTRUSTED` |
| No certificate revoked (leaked keyboxes) | live `android.googleapis.com/attestation/status`, fails closed when stale | `CERT_REVOKED`, `REVOCATION_UNAVAILABLE` |
| Intermediates within validity | key attestation | `CERT_EXPIRED` |
| Only the leaf carries the attestation extension (blocks "attested key signs a forged leaf") | key attestation | `ATTESTATION_EXTENSION_MISPLACED` |
| TEE or StrongBox, never software | key attestation | `SECURITY_LEVEL_TOO_LOW` |
| Bootloader locked, verified boot `VERIFIED` (or allow-listed custom OS key, e.g. GrapheneOS) | hardware root of trust | `BOOTLOADER_UNLOCKED`, `BOOT_STATE_UNVERIFIED`, `BOOT_STATE_SELF_SIGNED` |
| Key generated inside secure hardware | key attestation | `KEY_NOT_HARDWARE_GENERATED` |
| Your package + signing certificate | key attestation app ID | `PACKAGE_MISMATCH`, `SIGNING_CERT_MISMATCH`, `APP_ID_MISSING` |
| OS security patch age | key attestation | `OS_PATCH_TOO_OLD`, `OS_PATCH_UNKNOWN` |
| Reported brand/device/product/manufacturer/model = **hardware-attested** values | ID attestation | `DEVICE_ID_MISMATCH` |
| Play Integrity: request bound to this challenge + key, fresh, app recognized, `MEETS_DEVICE_INTEGRITY` | Google decode API | `PLAY_INTEGRITY_*`, `PLAY_APP_NOT_RECOGNIZED`, `PLAY_DEVICE_INTEGRITY_FAILED` |

Serial number, IMEI and MEID are never decoded, stored or logged.

## Protocol

```
app                                   service
 │ POST /v1/challenges ─────────────▶ │  {challengeId, nonce(b64url), expiresAt}
 │ generate EC key in AndroidKeyStore │
 │   with attestationChallenge=nonce  │
 │ requestHash = b64url(SHA-256(      │
 │   "device-trust/enroll/v1" ‖ nonce ‖ attested-key SPKI DER))
 │ Play Integrity token(requestHash)  │
 │ POST /v1/enrollments ────────────▶ │  {challengeId, attestationChain[b64 DER, leaf first],
 │                                    │   playIntegrityToken?, device{brand,device,product,manufacturer,model}}
 │ ◀──────────────────────────────────│  {decision: ALLOW|BLOCK, decisionId, deviceId?}
```

On ALLOW the attested public key is stored in the device registry (SQLite)
for Phase 2 device binding. Failure reasons are **not** returned to callers
unless `--expose-reasons` is set (development only); operators find them in the
`device_trust.decisions` log by `decisionId`.

Put this service behind your backend/API gateway so only authenticated app
sessions reach it.

## Run

```bash
python -m pip install -e 'service[test]'
python -m pytest service/tests -q

cp service/policy.example.json policy.json   # edit package + cert digests
device-trust serve --policy policy.json --db devices.sqlite \
    [--play-service-account service-account.json]
```

`signing_cert_sha256`: the SHA-256 of your app signing certificate (Play
Console → App integrity → App signing key certificate). Include the upload/debug
certificate only in non-production policies.

### Play Integrity (free tier)

1. Play Console → App integrity → link a Google Cloud project.
2. In that project, create a service account and download its JSON key.
3. Start the service with `--play-service-account`. Set
   `"require_play_integrity": true` once the app ships the client library.

If Play Integrity is not required and Google's API is unreachable, the
enrollment proceeds on key attestation alone and records the warning
`PLAY_INTEGRITY_UNAVAILABLE`. Devices without Google services are therefore
handled by key attestation only.

### Maintenance

* `device-trust refresh-roots` — re-download Google's attestation roots (review the diff before committing).
* `device-trust check-revocation` — confirm the revocation list is reachable.
* The revocation list is refreshed hourly in-process and fails closed after 48 h without a successful refresh.
* Challenges are kept in memory; run a single instance, or swap `ChallengeStore` for a shared store (Redis `SET NX EX` / `GETDEL`) before scaling out.

## Tests

* `tests/attestation_factory.py` builds synthetic chains (test root → batch
  intermediate → leaf with KeyDescription) to exercise every failure path,
  including the forged-leaf attack.
* `tests/test_real_chains.py` runs real Pixel / Sony attestation chains from
  Google's public test data (see `tests/fixtures/real/NOTICE.md`).

## Known limits

* Not physically verified on a production device in this repository yet: run
  the Android client against a staging deployment on real phones (locked
  Pixel, Samsung, an unlocked/rooted phone, an emulator) before relying on it.
* A device with a leaked-but-not-yet-revoked keybox can pass key attestation;
  `MEETS_STRONG_INTEGRITY` and later per-action re-attestation narrow that window.
* Phase 1 has no risk score: all checks are hard gates.
