# Device Trust Service

Server-side verification that an Android device is genuine, unmodified and
running your real app, before it is allowed to enroll for banking.

**The phone collects evidence; this service decides.** Client-side checks can
be hooked; hardware-signed evidence cannot be forged without a leaked key,
and leaked keys are on Google's revocation list, which this service enforces.

* **Phase 1 — enrollment** with hard-fail gates (ALLOW / BLOCK).
* **Phase 2 — device binding**: every sensitive action is signed by the
  enrolled hardware key (ALLOW / STEP_UP / BLOCK); high-risk actions need a
  biometric-bound confirm key.

* **Phase 3 — risk scoring**: client RASP signals, fresh Play Integrity
  signals, hardware evidence and history add up to an explainable score.

Policy tuning, dashboards and the red-team matrix (Phase 4) build on this.

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
 │ evidenceData = signed transcript   │  (Run 20; see docs/assurance/RUN_20_PROTOCOL.md)
 │ evidenceSignature = ECDSA(device key, evidenceData)
 │ requestHash = b64url(SHA-256(      │
 │   "device-trust/enroll-evidence/v1" ‖ evidenceData))
 │   (legacy unbound enrollment only: "device-trust/enroll/v1" ‖ nonce ‖ SPKI)
 │ Play Integrity token(requestHash)  │
 │ POST /v1/enrollments ────────────▶ │  {challengeId, attestationChain[b64 DER, leaf first],
 │                                    │   evidenceData, evidenceSignature, playIntegrityToken?,
 │                                    │   device{brand,device,product,manufacturer,model}, signals?}
 │ ◀──────────────────────────────────│  {decision: ALLOW|BLOCK, decisionId, deviceId?}
```

On ALLOW the attested public key is stored in the device registry (SQLite)
for Phase 2 device binding. Failure reasons are **not** returned to callers
unless `--expose-reasons` is set (development only); operators find them in the
`device_trust.decisions` log by `decisionId`.

Put this service behind your backend/API gateway so only authenticated app
sessions reach it.

## Phase 2: device binding and signed actions

At enrollment the app may send a second attestation chain, `confirmKeyChain`,
for a **confirm key**. The server only accepts it when the secure hardware
attests that the key:

* needs user authentication (`noAuthRequired` absent),
* accepts only a strong biometric (`userAuthType` = biometric; PIN/pattern
  only if `confirm_key_allow_device_credential`),
* needs a fresh authentication for every signature (`authTimeout` absent or 0),
* reports the same verified-boot key and attested IDs as the device key, and
  is a different key. This is a consistency check only: same-model phones share
  these facts, so it does **not** prove both keys are on one physical phone.

A bad confirm chain blocks the whole enrollment (`CONFIRM_KEY_INVALID`,
`CONFIRM_KEY_NOT_USER_AUTH_BOUND`); devices without strong biometrics simply
enroll without one.

### Signing an action

```
app                                   backend / trust service
 │ POST /v1/action-challenges {deviceId} ─▶  {challengeId, nonce, expiresAt}   (bound to that device)
 │ signedData = UTF-8 JSON:
 │   {"v":1,"deviceId","challengeId","nonce","ts":<ms>,
 │    "action":{"type":"payment","params":{...}}}
 │ signature = ECDSA-P256-SHA256(signedData) with the device key,
 │             or the confirm key after BiometricPrompt
 │ playIntegrityToken? with requestHash = b64url(SHA-256("device-trust/action/v1" ‖ signedData))
 │ POST /v1/actions/verify {deviceId, challengeId, signedData(b64), signature(b64),
 │                          key:"device"|"confirm", playIntegrityToken?}
 │ ◀── {decision: ALLOW|STEP_UP|BLOCK, decisionId, action?: {type, params}}
```

The server parses the exact signed bytes (no canonicalization; duplicate JSON
keys are rejected), checks they name this device, this challenge and its
nonce, that `ts` is fresh, and verifies the signature with the stored key.
**On ALLOW it returns the signed action; the backend must execute that
action, not whatever else arrived with the request.**

| Outcome | When |
|---|---|
| ALLOW | signature valid, bound, fresh, type allowed, Play Integrity OK if required |
| STEP_UP | only problem: the policy requires the confirm key for this action type (`CONFIRM_KEY_REQUIRED`) — ask for out-of-band verification |
| BLOCK | `DEVICE_UNKNOWN`, `DEVICE_REVOKED`, `CHALLENGE_UNKNOWN`, `SIGNED_DATA_MALFORMED`, `SIGNED_DATA_MISMATCH`, `ACTION_STALE`, `SIGNATURE_INVALID`, `ACTION_TYPE_NOT_ALLOWED`, `PLAY_INTEGRITY_*` |

Action params are never logged (they may contain account data); the action
type, key kind and reason codes are.

Policy keys: `allowed_action_types`, `confirm_key_required_actions`,
`play_integrity_required_actions`, `action_challenge_ttl_seconds`,
`action_max_age_seconds`, `confirm_key_allow_device_credential`
(see `policy.example.json`).

## Run 17: server-verified scan, key rotation and history

Full protocol, threat assumptions and tests: [RUN_17_VERIFIED_SCAN_HISTORY.md](../docs/RUN_17_VERIFIED_SCAN_HISTORY.md).

```
app                                   trust service
 │ POST /v1/device-challenges {deviceId, purpose:"scan"} ─▶ {challengeId, nonce, expiresAt}
 │ ephemeral key with attestationChallenge = nonce (deleted afterwards)
 │ scanData = {"v":1,"purpose":"scan","deviceId","challengeId","nonce","ts",
 │             "freshChainSha256":[...]|null,"device":{...},"signals":{...}|null}
 │ signature = ECDSA(enrolled device key, scanData)
 │ playIntegrityToken? with requestHash = b64url(SHA-256("device-trust/scan-evidence/v1" ‖ scanData))
 │ POST /v1/scans/verify {deviceId, challengeId, scanData, signature, freshAttestationChain?, playIntegrityToken?}
 │ ◀── {decision, decisionId, verifiedAt, freshUntil, policy{version,digest,verifierRuleset},
 │      evidence{deviceKeySignature,freshAttestation,playIntegrity,clientSignals}, coverage, history}
```

- The transcript is authenticated before any attestation or Play work.
- The fresh chain is verified with every enrollment hard gate. Enrolled or retired keys are never accepted as fresh, and scans do not add to keybox history.
- A verified fresh chain is stored as a minimal `scan_refresh` snapshot and compared with the previous one: patch, boot and attested-identity changes.
- A scan never changes the device's lifecycle state and never authorises a transaction.

**Key rotation:**
- `POST /v1/device-challenges {purpose:"key-rotation"}` issues a challenge.
- `POST /v1/key-rotations` then carries a transcript (domain `device-trust/key-rotation/v1`), signed by the current key and by the new key, plus the new attestation chain(s).
- Only ALLOW rotates, atomically. The device ID and history are kept, and the old key is retired forever.
- If the old key is lost, enroll again: that creates a new device record. Neither path proves the keys share one phone.

**Owner and admin views:**
- `GET /v1/devices/{id}/history` (gateway mode) returns attested history summaries and findings. It holds no evidence JSON or reasons.
- The admin device view includes the same history.

Policy keys: `policy_version`, `scan_challenge_ttl_seconds`, `scan_max_age_seconds`, `scan_result_ttl_seconds`, `scan_require_fresh_attestation` (default true), `scan_require_play_integrity`, `history_max_snapshots`.

## Phase 3: client signals and risk scoring

Hard gates still decide on their own (a bad signature or an unlocked
bootloader is BLOCK whatever the score). On top of them, every enrollment and
action gets a **risk score** from 0 to 100: each observed factor adds points
from a weight table, and per-action thresholds map the total to
ALLOW / STEP_UP (`RISK_STEP_UP`) / BLOCK (`RISK_BLOCK`).

**Inputs**

| Source | Factors (default points) |
|---|---|
| Client signals (`signals` object, see `signals.py`) | root: `root_su` 40, `root_magisk` 50, `root_apps` 25, `root_test_keys` 20, `root_system_rw` 40 · hooking: `hook_frida` 70, `hook_frida_port` 50, `hook_xposed` 60, `hook_zygisk` 50 · debugging: `debug_attached` 50, `debug_traced` 50, `debug_app_debuggable` 40 · emulator: `emu_build` 60, `emu_files` 60 · app: `app_installer_untrusted` 30, `app_signature_mismatch` 80 · scam/remote-control: `env_in_call` 25, `env_external_display` 30, `env_remote_access_apps` 15, `env_remote_access_a11y` 45, `env_a11y_third_party` 10 · `env_adb` 10, `env_dev_options` 5, `env_vpn` 5 · `client_signals_missing` 20 |
| Fresh Play Integrity token | `play_no_strong_integrity` 10, `play_capturing_apps` 25, `play_controlling_apps` 45, `play_overlay_apps` 15, `play_protect_*_risk` 10/25/50, `play_activity_level_3/4` 20/40, `play_unlicensed` 30 |
| Hardware evidence | `os_patch_stale` 10, `no_strongbox` 0 (informational) |
| History | `device_new` 10 (enrolled < 24 h), `velocity_high` 30 (≥ 30 actions/hour) |

Default thresholds: actions allow below 50 and block at 80; enrollment allows below 60 and
blocks at 90. Tune per action type under `risk.action_thresholds` (the example
policy makes `payment` and `add_payee` stricter) and override any weight under
`risk.weights`; unknown factor names are rejected so typos cannot silently
disable a check.

In signed actions the signal report sits **inside the signed bytes**, so a
proxy cannot strip or edit it. Code on a compromised phone can still lie,
which is why signals only add risk and never prove safety.

A STEP_UP **enrollment** is registered (the bank verifies the customer
out-of-band); a BLOCK enrollment is not.

**Audit trail.** Every decision is stored (`decisions` table) with its score,
factors and reason codes, never action params or raw signal reports. The
admin endpoint `GET /v1/admin/devices/{deviceId}` (admin token required)
returns status, attested facts and recent decisions for the fraud team.
With `--expose-reasons`, API responses also carry
`risk: {score, factors:[{factor, points}]}`.

## Run 6: attestation provenance and keybox defence

The professional bypass for hardware attestation is a **leaked factory
keybox** replayed by tools such as TrickyStore: the chain is genuinely signed
up to Google's root, so it passes every cryptographic check until Google
revokes it. Run 6 adds defences that work *before* revocation.

**Chain provenance.** Every verified chain is classified:

* `RKP`: exactly `leaf ← per-device key ← "Droid CA3" ← "Droid CA2" ← Google root`.
  The per-device key is short-lived and issued online by Google's Remote Key
  Provisioning. Only Google holds the Droid CA keys, so a leaked keybox cannot
  produce this shape (a fake "Droid CA3" signed by a keybox sits at the wrong
  position with the wrong issuer and is classified `FACTORY`).
* `FACTORY`: a keybox injected at manufacture: normal for older phones, and
  the only kind that leaks.

Verified on Google's real test chains (Pixel 8a/9 Pro/9a/10 TEE and StrongBox
→ RKP; Pixel 3, Sony → factory).

| Factor | Points | Meaning |
|---|---|---|
| `attestation_not_rkp_on_rkp_model` | 80 | Factory chain on a phone that only attests EC keys via RKP (Pixel 7 and newer; `risk.rkp_required_models`). Attested model, else reported model. |
| `attestation_factory_keybox_modern_os` | 10 | Factory chain on Android 14+ (weak on its own: many upgraded phones still use factory keys) |
| `attestation_key_model_conflict` | 80 | The same attestation key has been seen claiming two different models: a shared keybox. Re-evaluated on every action, so devices enrolled before the leak are flagged too. |
| `attestation_key_reuse` | 50 | ≥ `risk.keybox_reuse_threshold` (5) enrollments with one attestation key within `risk.keybox_window_seconds` (30 days) |
| `patch_spoofed` | 50 | `Build.VERSION.SECURITY_PATCH` reported by the app ≠ hardware-attested patch (property spoofing, e.g. PlayIntegrityFix) |
| `os_version_mismatch` | 40 | `Build.VERSION.RELEASE` major ≠ attested OS version |
| `patch_level_inconsistent` | 10 | OS vs vendor/boot patch more than 24 months apart (a genuine Pixel 3 shows 11 months, so the tolerance is wide) |

With defaults, a leaked keybox posing as a Pixel enrolls only as STEP_UP and
every action is BLOCKed. `"require_rkp": true` turns any non-RKP chain into a
hard failure (`ATTESTATION_NOT_RKP`). It is the strongest setting, but it rejects
phones that only have factory keys.

Every enrollment attempt (including blocked ones) records its attestation-key
hash and claimed model in `attestation_key_uses`.

## Run 12: fleet intelligence

Device farms and mule networks look normal one device at a time; they stand
out across the fleet. Every enrollment attempt (including failed ones) and
every action records a **keyed hash of the caller's network block** (/24 IPv4,
/48 IPv6; the address itself is never stored) and, for enrollments, a
**cohort**: attested model + patch level + key provenance.

| Factor | Points | Fires when (defaults, per `risk.fleet_window_seconds` = 1 h) |
|---|---|---|
| `fleet_network_burst` | 40 | ≥ 10 enrollment attempts from one network block |
| `fleet_cohort_burst` | 25 | ≥ 25 enrollments of one model/patch/key-type cohort |
| `fleet_network_many_devices` | 30 | ≥ 20 distinct enrolled devices acting from one network block |
| `fleet_device_recall_flagged` | 80 | A Play Integrity **device recall** bit in `risk.device_recall_fraud_bits` is set |

**Device recall** is Play Integrity's free per-device storage that survives app
reinstalls: when your fraud team confirms a device as fraudulent, write
`bitFirst` (or the bit you configure) for it via the Play Integrity API; every
later request from that phone then carries it, even after a reinstall.

Set `fleet_hash_key` in the policy (a long random secret) so hashes are
stable across restarts. Behind a proxy, start with `--trust-forwarded-for` so
the client IP comes from `X-Forwarded-For`; never enable it when the service
is reachable directly, or callers can forge their network.

`GET /v1/admin/fleet?hours=24` (admin token) lists the busiest network blocks,
cohorts and attestation keys for the fraud team.

Thresholds are starting points: tune them to your traffic, since a large
office or mobile carrier NAT legitimately puts many customers behind one block.

### Revoking a device

* CLI: `device-trust revoke --db devices.sqlite --device-id dev_... --reason "lost phone"`
* API (only when started with `--admin-token-file`, a file holding a ≥32-char token):
  `POST /v1/admin/devices/{deviceId}/revoke` with `Authorization: Bearer <token>`.
  Without the flag the endpoint does not exist.

Revoked devices get no new action challenges and every pending action is
blocked. Phase 1 databases are migrated in place on startup.

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
* Default risk weights are expert estimates, not yet calibrated on real
  traffic; tune them with data from a pilot before relying on STEP_UP rates.
* An enrolled key cannot be re-attested; to refresh attestation evidence
  (e.g. after an OS update) the app re-enrolls.
