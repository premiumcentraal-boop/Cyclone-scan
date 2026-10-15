# Run 17 — Server-verified scan, refresh, key continuity and history

Base: `run-16-device-lifecycle`, `78f8c7bedc62cbee5780146f15807044cdb66968` (Run 16 + Run 26, PR #17).
Branch: `run-17-verified-scan-history`. Physical device: UNVERIFIED. Live Google Play Integrity: UNVERIFIED.

This document was written before the implementation. It defines the protocol, the threat assumptions,
what the migration changes and the acceptance tests. The "Delivered" section at the end records what was built.

## 1. Two kinds of scan

| | Local diagnostic | Server-verified scan |
|---|---|---|
| Who decides | the phone itself (scanner `LocalRisk`) | the customer's verification service |
| Attestation | verified on the phone against bundled roots | verified by the server for a fresh, single-use challenge |
| Can be faked by code on the phone | yes | the fresh attestation chain cannot be forged without a hardware/keybox compromise; client signals still can |
| Shown as | "Local diagnostic — not server-verified" | a server verdict with decision ID, verification time, `freshUntil`, policy traceability and per-evidence status |

The scanner and SDK never label a local result, a failed request or an unreachable server as server-verified.
The SDK returns either `ServerScan.Verified` (the server answered with a verdict) or `ServerScan.Unavailable` (with a reason).
A pure function, `ServerScan.label(now)`, maps the outcome onto one display label:
- `VERIFIED_FRESH`
- `VERIFIED_PARTIAL` — the server verified the signature, but fresh attestation or Play evidence was missing, failed or unavailable
- `VERIFIED_EXPIRED` — past `freshUntil`
- `REJECTED` — BLOCK
- `UNAVAILABLE`

## 2. Protocol

### 2.1 Device challenge

`POST /v1/device-challenges {"deviceId", "purpose": "scan" | "key-rotation"}` → `{challengeId, nonce, expiresAt}` (201).

- Rules match action challenges:
  - owner-scoped by principal
  - the device must be `active`
  - with `require_bound_device`, the device must also be `BOUND`
- Otherwise the server returns 404, the same answer for unknown, not-owned, pending, revoked and quarantined devices.
- The challenge is bound to `"<purpose>:<deviceId>"`. Scan, key-rotation, action and enrollment challenges are therefore not interchangeable. The store pops a challenge on any lookup.
- TTL: `scan_challenge_ttl_seconds` (default 120).

### 2.2 Scan transcript (signed by the enrolled device key)

Exact UTF-8 JSON bytes. Field order is not canonical, and the server parses the bytes it verifies.

```json
{"v": 1, "purpose": "scan", "deviceId": "...", "challengeId": "...", "nonce": "<b64url>",
 "ts": <epoch ms>, "freshChainSha256": ["<hex>", ...] | null,
 "device": {"brand": ..., "model": ...}, "signals": {...} | null}
```

- The field set is exact. Unknown, duplicate or missing fields are rejected (strict JSON: 32 KiB, depth 32, 8,192 nodes).
- `freshChainSha256` lists ordered SHA-256 digests of the submitted fresh attestation chain. It is `null` only when no chain is submitted, and a chain that does not match it is rejected. Removing the chain while keeping the digests, or the reverse, is a mismatch.
- `device` carries reported Build fields. They are used only for the `DEVICE_ID_MISMATCH` comparison against the fresh attestation. They are never stored in a snapshot or promoted to attested facts.
- `signals` is the whole Run 14 report, coverage fields included, snapshotted once before signing.
- Signature: ECDSA P-256/SHA-256 by the **enrolled device key** (`record.public_key_spki`), using the existing `verify_signature` helper.
- Freshness: `ts` must be within `clock_skew_seconds` in the future and `scan_max_age_seconds` (default 120) in the past.
- Scan domain bytes are new in this run: `device-trust/scan-evidence/v1`.
  - Play `requestHash` = unpadded base64url(SHA-256(domain ‖ exact transcript bytes)).
  - A Play token minted for enrollment (`device-trust/enroll-evidence/v1`) or an action (`device-trust/action/v1`) therefore cannot be replayed into a scan.

### 2.3 Fresh attestation

The attestation challenge is fixed when a key is generated, so the enrolled key cannot be re-attested. For a fresh observation, the SDK generates an **ephemeral** hardware key whose attestation challenge is the scan nonce, then deletes it after the request.

The server:
- verifies that chain with the normal `AttestationVerifier` and the scan nonce. Every hard gate is applied again: root, revocation, boot state, lock, security level, app identity, patch age, reported IDs.
- rejects a chain whose leaf **is** the enrolled key or any key enrolled/retired in the registry (`FRESH_ATTESTATION_KEY_REUSED`). Re-sending the enrollment certificate is never fresh evidence; its nonce would not match anyway.
- never registers the ephemeral key and never lets it sign anything.
- does not count the fresh chain as an enrollment in keybox history. It only reads the keybox statistics, so repeated scans cannot inflate a keybox's enrollment counter.

`scan_require_fresh_attestation` defaults to true. A scan without a fresh chain then gets `SCAN_FRESH_ATTESTATION_MISSING` and BLOCK. When an operator sets it to false, the result says `freshAttestation: NOT_PROVIDED` and the client label is `VERIFIED_PARTIAL`.

### 2.4 Play Integrity

- An optional `playIntegrityToken` is decoded by the configured decoder. That is the existing real `GoogleApiDecoder`, wired through `serve --play-service-account`.
- `scan_require_play_integrity` (default false) makes a missing or undecodable verdict a blocking reason. Otherwise it is a warning.
- The result reports one of five statuses:
  - `VERIFIED`
  - `FAILED` — decoded, with failing verdict reasons
  - `UNAVAILABLE` — no decoder configured, or the decode call or credentials failed
  - `NOT_PROVIDED` — the app sent no token
  - `NOT_REQUESTED` — client side only: no Cloud project configured

Automated tests use fake decoders. A fake verdict is not live Google evidence.

### 2.5 Result

`POST /v1/scans/verify` → 200:

```json
{"decision": "ALLOW|STEP_UP|BLOCK", "decisionId": "dec_...", "verifiedAt": <ms>, "freshUntil": <ms>,
 "policy": {"version": "<operator label>", "digest": "<16 hex>", "verifierRuleset": "run15-attestation-v1"},
 "evidence": {"deviceKeySignature": "VERIFIED|FAILED", "freshAttestation": "VERIFIED|FAILED|NOT_PROVIDED",
              "playIntegrity": "VERIFIED|FAILED|UNAVAILABLE|NOT_PROVIDED", "clientSignals": "SIGNED|MALFORMED|NOT_PROVIDED"},
 "coverage": {"DETECTED": n, ...} | null,
 "history": {"snapshots": n, "previousAt": <s> | null, "previousSource": "...", "changes": [{"code","level","field"}]},
 "reasons"/"warnings"/"risk": only with --expose-reasons}
```

- `policy.digest` is the SHA-256 of the policy's canonical JSON with secrets removed (`fleet_hash_key`). An operator can match a result to a policy file without the label being trusted.
- `freshUntil` = `verifiedAt` + `scan_result_ttl_seconds` (default 300). It is a display/caching bound, not a guarantee that the phone stays unchanged.
- `history.changes` uses the Run 22 diagnostic vocabulary and two new informational codes (§3). These describe the device's own attested facts, not policy internals, so they are shown to the owner. Reason codes and risk factors stay behind `--expose-reasons`, as before.
- Decisions are logged as `kind = 'scan'`. The scan endpoint never executes a business transaction and never changes lifecycle state.

### 2.6 Key rotation (continuity with old-key authorization)

A new attested key never silently replaces an enrolled key. There are two paths:

1. **Old key available — rotation.**
   - The client generates a new device key, plus an optional new confirm key, with the key-rotation nonce as attestation challenge. It sends `POST /v1/devices/key-rotation` with:
     - a transcript `{"v":1,"purpose":"key-rotation","deviceId","challengeId","nonce","ts","newChainSha256":[..],"newConfirmChainSha256":[..]|null,"device":{..}}`
     - `oldKeySignature`, by the currently enrolled device key
     - `newKeySignature`, by the new key: proof of possession
   - Domain: `device-trust/key-rotation/v1`. The server applies the enrollment hard gates and risk to the new chain, and the Run 2 confirm-key rules to a new confirm chain.
   - Only an ALLOW rotates. STEP_UP and BLOCK change nothing; the user takes path 2.
   - The registry update is a single compare-and-swap on (device_id, current key, status active). The old key goes into `retired_keys` and can never enroll or rotate again. A lifecycle event `key_rotated` (active → active) and a `key_rotation` snapshot are written in the same transaction.
   - Two concurrent rotations from the same old key: exactly one succeeds. The other gets `KEY_ROTATION_CONFLICT`.
2. **Old key lost** (reset, reinstall, keystore wiped, confirm key invalidated without a usable device key): authenticated new enrollment, exactly as in Run 16. It creates a new device record. The owner or admin revokes the old one; recovery is the customer's account process.

Neither path proves the old and new keys are physically on one phone. Rotation proves that the holder of the enrolled key authorised the new key. That holder may be malware with use of the key on a compromised phone; matching model or boot facts do not change this. Revoked, pending and quarantined devices cannot rotate, and tenant isolation is unchanged.

## 3. History

- Existing `assurance_snapshots`, v1, additive fields:
  - `source`: `enrollment` | `scan_refresh` | `key_rotation`. Missing means a pre-Run-17 snapshot, which only enrollment wrote. It is reported as `enrollment_legacy`.
  - `device_key_sha256`: the enrolled device key at the time. Missing means `leaf_spki_sha256`, which held for every pre-Run-17 row.
  - `authorized_by_sha256`: rotation only; the old key that signed.
- Snapshots record only the minimal attested measurements already defined by Run 22. They hold no reported Build fields, signals, tokens, IP or params.
- `evidence_history.compare_continuity(previous, current)`:
  - Continuity holds when `current.device_key_sha256 == previous.device_key_sha256`, or when the current snapshot is a rotation authorised by `previous.device_key_sha256`.
  - Otherwise: `KEY_CONTINUITY_UNVERIFIED`, exactly as before.
  - When continuity holds and the leaf differs (ephemeral or rotated key), the Run 22 `compare` runs on the attested device fields. It adds one INFO finding:
    - `FRESH_KEY_AUTHORIZED` for a scan refresh
    - `KEY_ROTATED` for a rotation
  - These are diagnostics, not reason codes or risk weights.
- Retention: the enrollment snapshot is always kept. At most `history_max_snapshots` (default 50) later snapshots are kept per device, oldest pruned in the same transaction.
- Owner view (gateway mode): `GET /v1/devices/{id}/history` returns the bounded snapshot list (time, source, security level, boot state, lock, patch levels) with its comparison findings. It never includes evidence JSON, reported fields or backend reasons. The admin device view gains the same history.

## 4. Migration

- Schema migration 3 adds `retired_keys (spki_sha256 PRIMARY KEY, device_id, retired_at)`.
- Version 2 databases from Run 16 upgrade in place. Older version 0/1 databases go through migrations 1–3 in order.
- Existing snapshots are untouched and are read with the legacy defaults above. A version 4 database is refused.
- `register` refuses keys in `retired_keys` (`KEY_ALREADY_ENROLLED`).

## 5. Threat assumptions

- **In scope:**
  - network attacker or proxy: replay, stripping or editing fields, swapping chains
  - another tenant or account
  - stale or reused challenges, tokens and certificates
  - downgrade: dropping fresh attestation or Play, old versions, cross-purpose transcripts
  - concurrent duplicate requests
  - unavailable Google services
- **Not in scope / not claimed:**
  - Code running on the phone with use of the enrolled key can sign lies in `signals` and can attach a fresh chain from a different phone. Co-residency is not proven.
  - A leaked keybox can forge attestation (Run 6 provenance heuristics still apply).
  - Exactly-once execution of a business transaction is the customer backend's job. Scans do not authorise transactions.
  - "Server-verified" means verified against the configured policy at `verifiedAt`. It is not a certification.

## 6. Acceptance tests

- **Happy path:** a scan with fresh attestation → ALLOW; `VERIFIED` statuses; a `scan_refresh` snapshot; history compared against enrollment with `FRESH_KEY_AUTHORIZED`.
- **Replay:** the same body twice → `CHALLENGE_UNKNOWN`.
- **Wrong owner/tenant:**
  - no challenge (404)
  - a body signed for Alice's device but posted as Bob → `DEVICE_UNKNOWN`
- **Wrong key:** signed by another key → `SIGNATURE_INVALID`.
- **Expired challenge**, and **stale or future `ts`**.
- **Altered payload:**
  - an edited field after signing, or an extra or missing field → `SCAN_EVIDENCE_MALFORMED` / `SIGNATURE_INVALID`
  - mismatched `deviceId`, challenge or nonce, or a chain swapped against the digests → `SCAN_EVIDENCE_MISMATCH`
- **Cross-purpose:** an action or enrollment challenge used for a scan, a scan challenge used for an action, or key-rotation and scan challenges swapped → `CHALLENGE_UNKNOWN`.
- **Downgrade:**
  - fresh attestation removed → `SCAN_FRESH_ATTESTATION_MISSING`
  - the enrollment chain re-sent → nonce/`FRESH_ATTESTATION_KEY_REUSED`
  - transcript `v: 0` or purpose `enrollment`
  - a Play token for another hash → `PLAY_INTEGRITY_REQUEST_MISMATCH`
- **Fresh evidence regressions:** an unlocked bootloader in the fresh chain → BLOCK; `PATCH_REGRESSION` / `BOOT_EVIDENCE_CHANGED` findings shown.
- **Device state:** revoked, pending and quarantined devices → no challenge; direct verify → `DEVICE_REVOKED` / `DEVICE_PENDING` / `DEVICE_REBINDING_REQUIRED`.
- **Concurrency:**
  - N parallel verifies of one challenge → exactly one is accepted
  - parallel rotations from one old key → exactly one succeeds
- **Rotation:**
  - success keeps the device ID and uses the new key for actions; the old key's signatures fail
  - the old key cannot enroll again
  - missing or invalid old-key or new-key signature → refused
  - STEP_UP or BLOCK → nothing changes
  - the confirm key is replaced or removed as submitted
  - the history chain shows `KEY_ROTATED`
- **Snapshots:**
  - old (pre-Run-17) snapshots compare correctly with the new ones
  - retention bound holds
  - migration from version 2 with snapshots retained, then 3 → refuse 4
- **Unavailable services:**
  - no decoder → `UNAVAILABLE` warning, or a reason when required
  - decoder raising → `UNAVAILABLE`
- **SDK (JVM):**
  - transcript field set and server cross-check fixture
  - ephemeral key deleted on success and failure
  - `Unavailable` on 404, network failure and malformed response; never `Verified`
  - label function including expiry
  - rotation saves the new aliases only on ALLOW
- **CI:** a Kotlin-generated scan transcript passes the server's strict scan parser (`tools/check_scan_fixtures.py`).

## Delivered

- **Service:**
  - `scan_evidence.py`: strict transcripts, domains and builders.
  - `service.py`:
    - `issue_device_challenge`, `verify_scan` and `rotate_key`
    - a shared lifecycle gate
    - owner and admin history views
  - `registry.py`:
    - migration 3
    - `retired_keys`, `key_known`, `record_snapshot` with retention
    - a compare-and-swap `rotate_key`
    - explicit-column snapshot inserts
  - `evidence_history.py`: snapshot sources, `compare_continuity` and `summary`.
  - `policy.py`: the Run 17 keys and a secret-free `digest()`.
  - `api.py`:
    - `/v1/device-challenges`, `/v1/scans/verify`, `/v1/key-rotations`
    - `/v1/devices/{id}/history` (gateway mode)
  - Seven new reason codes.
- **SDK:**
  - `ScanEvidence.kt`: transcripts and result models, including `ServerScan`, its labels and `UnavailableReason`.
  - `TrustJson`: strict parsing; a malformed response is never `Verified`.
  - `HttpTrustApi` routes.
  - `DeviceTrustClient.verifiedScan()`: ephemeral key deleted in `finally`; every remote failure maps to `Unavailable`.
  - `DeviceTrustClient.rotateKeys()`: switches aliases only when the server reports `rotated`.
  - New `TrustApi` methods have default bodies, so existing custom transports still compile.
- **Scanner 0.8.0 (versionCode 5):**
  - Server tab: verified-scan card with per-evidence rows, policy traceability and freshness, plain-language history findings.
  - Optional Cloud project number for Play Integrity; a key rotation button.
  - Wording rules live in the pure `ServerScanView` and are unit-tested.
- **CI:** a new step, `tools/check_scan_fixtures.py`, parses Kotlin-generated maximum-size scan and rotation transcripts with the server's strict parser.

Scope boundaries kept:
- Native code (`android/devicetrust/src/main/cpp`) is untouched; it is the Run 27 native-review area.
- No Run 20–26 file was rewritten. `evidence_history.compare` and `snapshot` were extended additively, and `compare` itself is unchanged.
- Pending expiry still runs only on the completion path; there is no background scheduler.

Known limitations:
- If a rotation response is lost after the server rotated, the app still holds the old (retired) key and must enroll again.
- Scan risk uses the enrollment thresholds (`action_type=None`).
- The fresh chain proves the current state of *some* hardware that ran the app's attestation for this nonce. Code with use of the enrolled key could attach another phone's chain.
- Live Google decoding and physical devices are untested; that is Run 19.
