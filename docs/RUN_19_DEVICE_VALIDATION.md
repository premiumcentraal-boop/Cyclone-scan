# Run 19 — Device validation and beta candidate

Base: `run-18-beta-packaging`, `7b05048` (PR #19). Branch: `run-19-device-validation`.

**Status: physical validation BLOCKED: no test device is reachable from the agent environment.** This run delivers:
- the connectivity record
- the executable runbook for the 17-case lab matrix
- a real beta-checklist run against the exact CI candidate, with its result **NO_GO**

No physical, emulator or live-Google observation has been created, and none is claimed.

## Connectivity, checked afresh (15 October 2026)

| Path | Result |
|---|---|
| Phone gateway tool | not available in this session (the previous session reported DEVICE_DISCONNECTED) |
| `adb devices` (platform-tools 35, agent container) | daemon started; **no devices attached** |
| Android emulator | not possible: no `/dev/kvm`, no hardware virtualization flags |
| Live Google Play Integrity | no Cloud project, service account or Play-recognized build configured |

The candidate cannot be run on a phone from here. The `emulator` lab case also stays NOT_RUN: an emulator observation must come from a declared emulator, never from host tests.

## Candidate under test

The Run 18 CI build of `7b05048`: [run 38674219916](https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38674219916), APK artifact 11945646310. It is recorded in [docs/validation/candidate.json](validation/candidate.json) with the unedited `build-evidence.json` and `scanner-assurance-manifest.json`.

| | |
|---|---|
| Tested (merge) revision | `a3ad8978e2c736901d54a7f4c416bf3541a8e541` |
| Scanner APK SHA-256 | `008209744c920a80580b69182a2651ec0cffd547a29cbe4223305617beb91c61` |
| SDK AAR SHA-256 | `cfec9555f299d3be8f7377d454b60156963af269e707e57634e9188bbef5ebb7`: byte-identical across two separate CI runs (38673627448 and 38674219916) and after a `--rerun-tasks` rebuild |
| Signer (apksigner) | `a3be9322210b985228ab17325b256403448e5035fcc5e4d2812ca9238abe45ee`: **TEST_DEBUG_KEY**, the CI runner's debug key |
| Version | 0.9.0-beta.1 (versionCode 6) |

Install exactly that APK, from the CI artifact, on each test phone. A local rebuild is a different APK identity, and its observations do not count for this candidate.

## Runbook (operator, on authorized devices only)

**Setup:**
- Run the reference service (docs/DEPLOYMENT.md), or `device-trust serve --expose-reasons` on a lab laptop.
- Put the candidate's package and its CI signer digest in the policy.
- For the Play cases, use a Play-recognized build and a configured service account. Otherwise record Play as UNAVAILABLE.

**Never collect:** IMEI, serial numbers, account data, credentials, OTPs or raw logs. Use one stable anonymous alias per phone, e.g. `pixel-a`.

For every case:
1. Scan tab (local diagnostic). Then Server tab: run the server test, then **Run server-verified scan** twice (`repeat_scan` uses the second).
2. Note the following:
   - local verdict and score
   - server decision and label (VERIFIED_FRESH / PARTIAL / EXPIRED / REJECTED / UNAVAILABLE)
   - evidence rows, coverage counts and history findings
   - duration in milliseconds, and whether anything crashed
3. Compare with the expectation below. Only then set `expectation_met`; `operator_verified` is true only after review.
4. Record with `python -m tools.assurance.lab record lab.json observation.json`. The schema is in `tools/assurance/lab.py`, with `origin` set to PHYSICAL (EMULATOR only for `emulator`) and the candidate's `revision`/`apk_sha256`.

| Case | Device / configuration | Expected (what "met" means) |
|---|---|---|
| clean_pixel | stock, locked Pixel | Enrollment ALLOW (RKP chain). Verified scan VERIFIED_FRESH, or PARTIAL only for Play if Play is not configured. No REVIEW history findings. |
| clean_samsung | stock, locked Samsung | Same as clean_pixel. A FACTORY or UNRECOGNIZED chain is a recorded note, not a failure. |
| clean_tee | TEE-only phone (no StrongBox) | ALLOW. `no_strongbox` is informational only. |
| bootloader_unlocked | designated lab unit | Enrollment BLOCK `BOOTLOADER_UNLOCKED`; any fresh scan BLOCK; local hard finding. |
| rooted_hidden | designated lab configuration | Root or hook signals raise risk, or attestation fails. A miss is recorded as a miss, never removed. |
| frida_inprocess / lsposed_inprocess | the scanner itself only. **Coordinate with the Run 27 native-review owner.** | Native/Kotlin hooking findings; server risk STEP_UP or BLOCK. |
| repackaged | scanner re-signed with another key | `SIGNING_CERT_MISMATCH` (attestation app ID). |
| emulator | declared emulator | Attestation fails or is software-level → BLOCK; local emulator findings. |
| custom_rom | e.g. GrapheneOS, locked | Without an allow-listed boot key: BOOT_STATE_SELF_SIGNED. With `allowed_self_signed_boot_keys`: ALLOW. A legitimate configuration, not "malicious". |
| offline | airplane mode for the server step | The scanner shows **"Not server-verified"** (UNAVAILABLE), never a server verdict. The local diagnostic still works. |
| no_gms | device without Google services | Play UNAVAILABLE / not requested. Attestation decides. |
| accessibility_legitimate | ordinary screen reader on | Not BLOCK on that alone. Note the risk factors seen. |
| vpn_legitimate | ordinary VPN | `env_vpn` is informational (5 points); not BLOCK. |
| remote_support_legitimate | owner-authorized support session | STEP_UP is acceptable; BLOCK must be explained by other evidence. |
| repeat_scan | any clean phone, 2+ verified scans | No crash. History compared, `FRESH_KEY_AUTHORIZED`, snapshot count grows. |
| biometric | owner-configured strong biometric | Confirm key created; biometric payment ALLOW; cancel → no signature. |

The pilot review prerequisite is at least five clean-device aliases and three altered-device aliases (Run 24). It is not a statistical accuracy claim. Do not tune weights to make a hard cryptographic failure pass.

Then run the gate (§ below) with the filled-in lab file and a review document whose approvals reference real retained evidence.

## Beta checklist: actual run on the candidate

Files are in [docs/validation/](validation/):
- `lab.json`: initialized and **empty**, because no observation exists
- `beta-review.json`: the review declarations, see below
- `beta-gate-result.json`: the tool's unedited output

Review declarations (honest state):
- `candidate_ci`: **PASS**. Its evidence digest is the SHA-256 of the CI `build-evidence.json` for this exact candidate, kept in `docs/validation/`.
- All other approval categories: **UNVERIFIED**. They cover integrated Claude runs (no human review yet), attestation compatibility on real OEMs, device lifecycle on devices, live Google verification, stable signing (none), protocol review, privacy/retention review and dependency licences (owner decision open).
- Policy `reviewed: false`. The thresholds are the enrollment defaults (60/90) as placeholders, not approved acceptance limits.

**Result: `NO_GO`, with 31 blockers:**
- all 17 lab cases
- `pilot_sample`, `clean_intervention`, `altered_miss`, `latency_p95` and `no_observed_crashes` (no observations)
- `policy_review`
- the eight UNVERIFIED approvals

The tool exited 1, as designed for NO_GO. `service/tests/test_validation_record.py` re-runs the gate on the committed files: the record must match the tool's output and the candidate, and must stay NO_GO while the lab file is empty. This is the correct outcome. An all-pass result would mean only READY_FOR_HUMAN_REVIEW, never publication or certification.

## What would unblock Run 19

1. A reachable authorized phone: a reconnected gateway, or adb access in a session that has one.
2. A Play-recognized build with Cloud project and service account, for `live_google_verification`.
3. The owner's signing identity (Run 18 secrets) and licence decision.
4. Coordination with the Run 27 native-review owner for the altered-configuration cases.
