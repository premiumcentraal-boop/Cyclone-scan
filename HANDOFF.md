# Cyclone-scan — build handoff

Android device-integrity / anti-fraud SDK for neo-banks: an Android client library
plus a Python decision service. The phone gathers hardware-signed evidence and
device signals; **the server makes every ALLOW / STEP_UP / BLOCK decision.**

**Current state (Run 14):** the delegated Run 14–19 plan and its living build log are in
[docs/BUILD_LOG.md](docs/BUILD_LOG.md). PR #6 stacks `run-13-native-integrity` on #5, and the
Run 14 PR stacks `run-14-report-coverage` on #6; the branch table below predates them.

This file is the pick-up point for another agent. Earlier runs below are built, tested and pushed. Run 13 additions are described in
[docs/RUN_13_NATIVE.md](docs/RUN_13_NATIVE.md); see the latest PR CI for validation. Nothing has been run on a physical device yet (deliberate:
real-device verification is scheduled after the build runs).

GitHub: `premiumcentraal-boop/Cyclone-scan` (shown as `Cyclone-scan`; clone remote
uses that capitalisation).

## Repo layout

```
service/            Python decision service (FastAPI). Makes all decisions.
  device_trust/     der, key_description, attestation, revocation, roots, policy,
                    challenges, registry, play_integrity, actions, risk, signals,
                    fleet, service, api, cli, reasons
  tests/            pytest; fixtures/real/ holds Google's public attestation chains
  policy.example.json
android/
  devicetrust/      Kotlin client library (:devicetrust), minSdk 26
  scanner/          Test APK (:scanner): scans the phone it runs on, shows verdict
testvectors/        risk_vectors.json + generate_risk_vectors.py (engine parity)
README.md           roadmap + per-area docs
```

## Branch / PR chain (each stacked on the previous)

| PR | Branch | Base | Contents |
|----|--------|------|----------|
| #1 | `phase-2-device-binding` | `main` | Phase 1 (enrollment verifier) + Phase 2 |
| #2 | `phase-3-risk-signals` | `phase-2-device-binding` | Phase 3 risk signals |
| #3 | `phase-4-scanner-app` | `phase-3-risk-signals` | Scanner test APK |
| #4 | `run-6-keybox-hardening` | `phase-4-scanner-app` | Run 6 attestation provenance |
| #5 | `run-12-fleet-intelligence` | `run-6-keybox-hardening` | Run 12 fleet intelligence |

All five are **open drafts with green CI**. `main` currently holds only Phase 1.
**Merge in order #1 → #5.** After merging, new work branches from `main`.
`HEAD` is currently `run-12-fleet-intelligence` (commit 7352e67).

Commit chain:
```
7352e67 Run 12: fleet intelligence
520201c Run 6: attestation provenance and leaked-keybox defence
9412eca Scanner test APK
e686ffe Phase 3: client RASP signals and explainable risk scoring
e623483 Phase 2: device binding, biometric confirm key and signed actions
f127464 Phase 1: enrollment verifier + Android client
```

## What each run delivered

**Phase 1 — enrollment verifier (on `main` + PR #1).**
Android hardware key attestation: strict DER parser (`der.py`), KeyDescription
parser (`key_description.py`), chain verifier (`attestation.py`) checking Google
roots (`trust_anchors/google_roots.json`, RSA + 2025 EC CA), chain signatures,
leaf-only extension, live Google revocation list (`revocation.py`, fails closed),
TEE/StrongBox level, locked bootloader, verified boot, key origin, app
package+signing-cert, OS patch age, and attested vs reported device model.
Serial/IMEI/MEID are never decoded. Single-use challenges (`challenges.py`),
SQLite device registry (`registry.py`), FastAPI (`api.py`), CLI (`cli.py`).
Play Integrity standard-token decode via Google API (`play_integrity.py`).

**Phase 2 — device binding (PR #1).**
Per-action signing: app signs exact JSON bytes (device, challenge, nonce,
timestamp, action type+params) with the enrolled hardware key (`actions.py`);
server parses those bytes (duplicate keys rejected), checks binding+freshness,
verifies ECDSA-P256, returns the signed action on ALLOW. Decisions
ALLOW/STEP_UP/BLOCK. Optional biometric-bound confirm key, accepted only if the
hardware attests user-auth required, strong-biometric-only, per-use (no timeout),
same hardware, different key. Device revocation (CLI + admin-token API). Registry
migrates in place.

**Phase 3 — device signals + risk engine (PR #2).**
`signals.py`: strict versioned client report (root/hook/debug/emulator/app-
integrity/environment indicators). `risk.py`: tunable weight table → 0–100 score,
capped, per-action + enrollment thresholds → ALLOW/STEP_UP/BLOCK; hard gates
always win. Signals are signed inside the action bytes. Decision audit table +
admin device-detail endpoint. Android `DeviceSignals` collector behind a
`SignalProbe` seam (+ `AndroidSignalProbe`, never throws), `SecureWindow` helper.

**Scanner APK (PR #3).**
`android/scanner`, Jetpack Compose. Tabs: Scan (local verdict with full check
list + score + shareable privacy-safe JSON), Biometric (confirm-key demo), Server
(full flow against a running service). Kotlin ports of der/key_description/chain-
verifier/risk engine. `testvectors/risk_vectors.json` generated from the Python
engine and replayed by BOTH Python and Kotlin test suites → engines cannot drift.

**Run 6 — attestation provenance (PR #4).**
Classifies each verified chain as `RKP` (Google per-device provisioned:
leaf←per-device←Droid CA3←Droid CA2←root) or `FACTORY` (manufacture-time keybox,
the leakable kind). Factory keybox on an RKP-only model (Pixel 7+) = +80; one
attestation key seen on 2 models (+80, re-checked every action); key reused ≥5×/30d
(+50); reported SECURITY_PATCH≠attested (+50); reported RELEASE≠attested OS (+40);
factory on Android 14+ (+10); patch levels >24mo apart (+10). Optional `require_rkp`
hard gate. `attestation_key_uses` fleet table. Scanner 0.5.0 shows provenance.

**Run 12 — fleet intelligence (PR #5, service-only).**
Keyed HMAC of caller network block (/24 v4, /48 v6; raw IP never stored) + cohort
(model+patch+provenance) recorded per attempt. Factors: network enrollment burst
(+40), cohort burst (+25), many devices per network (+30), Play Integrity device-
recall bit set (+80). Admin `GET /v1/admin/fleet`. `--trust-forwarded-for` off by
default; `fleet_hash_key` policy secret.

## Test status (all green, run from repo root)

- `cd service && python -m pip install -e '.[test]' && python -m pytest -q` → **257 pass**
- `cd android && ./gradlew :devicetrust:testDebugUnitTest :scanner:testReleaseUnitTest
  :scanner:assembleRelease :devicetrust:lintRelease` → SDK 53, scanner 15, lint clean,
  APK builds. Set `android/local.properties` `sdk.dir`, or `ANDROID_HOME`.
- `python testvectors/generate_risk_vectors.py` regenerates vectors; a Python test
  fails if the committed file is stale. Both engines must match it.

## Conventions to keep

- Every run = its own branch stacked on the previous, draft PR, green CI, honest
  "physical device: UNVERIFIED" note. Mutation-check new logic (break it, see a test fail).
- Any new risk factor: add the weight in `risk.py` AND `LocalRisk.kt`, a plain-English
  description in both, and a case in `generate_risk_vectors.py`; regenerate; both
  suites must pass. This parity harness is the main guardrail — do not bypass it.
- Never store serial/IMEI/MEID, raw IPs, action params, or secrets.
- CI workflow: `.github/workflows/ci.yml` (builds both, uploads the scanner APK).

## Run 13 pickup

Next stacked branch: `run-13-native-integrity`, based on `f12704459b0535022b84957ea357f507e266c2d8`.
Native collector, schema/risk parity, scanner 0.6.0 and regression details: [run notes](docs/RUN_13_NATIVE.md).
The earlier HEAD and counts in this handoff describe the previous run, not Run 13.
Physical device remains UNVERIFIED. Confirm-key matching is consistency evidence, not proof of physical co-residency.

## Remaining roadmap (not built)

- Native v1 is implemented on the Run 13 branch; real-device validation and broader self-integrity coverage remain.
- SDK self-protection (obfuscation, encrypted strings, runtime self-integrity).
- Continuous in-app monitoring with signed events.
- Scam/malware depth (overlay abuse, known-malicious app lists, accessibility abuse).
- Production backbone (Postgres, Redis-backed challenges, rate limiting, Docker,
  load tests) — **selected as the next run; not yet started.**
- Attack-lab benchmark matrix; then real-device verification.

Risk weights and thresholds throughout are expert estimates, not yet calibrated
on real traffic. Tune against pilot data before relying on exact STEP_UP/BLOCK rates.
