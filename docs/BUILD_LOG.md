# Cyclone Scan — living build log

Delegation plan of 14 October 2026 (Runs 14–19). Update after every run. Never mark planned work complete before evidence exists.

Status vocabulary: PLANNED, IN_PROGRESS, IMPLEMENTED, CI_PASSED, DEVICE_VERIFIED, BLOCKED. CI_PASSED does not imply DEVICE_VERIFIED or release approval.

| Run | State | Base / head | PR / CI | Device evidence | Notes |
|---|---|---|---|---|---|
| 13 baseline | CI_PASSED | d4667c169a3f1fc2475be940390ec69429c92b06 | PR #6; CI 38482579680 | UNVERIFIED | Scanner 0.6.0; 282 Python tests; 58 vectors |
| 14 report coverage | CI_PASSED | d4667c1 → 63fd3bd | PR #8 (ready for review); CI 38646802172 | UNVERIFIED | Scanner 0.7.0; 303 Python tests; 59 vectors |
| 15 verifier compatibility | CI_PASSED | 63fd3bd → 3d68781 | PR #14; CI 38648998069 | UNVERIFIED | 335 Python tests; 60 risk + 14 attestation vectors |
| 15b integrate Runs 20–25 | CI_PASSED | 69e3bc5 + 2cd8d99 → 04996b5 | PR #15; CI 38650877770 | UNVERIFIED | Merge of the parallel stack; 390 Python tests |
| 16 device lifecycle | CI_PASSED | 04996b5 → e042e7d | PR #17; CI 38652134596 | UNVERIFIED | 408 Python tests; states, ownership, migrations |
| 17 server scan/history | CI_PASSED | 78f8c7b → 07039e1 | PR #18; CI 38667401633 | UNVERIFIED | 488 Python tests; scanner 0.8.0; live Google decode not exercised |
| 18 beta packaging | CI_PASSED | 165d639 → 7b05048 | PR #19; CI 38673627448, 38674219916 | UNVERIFIED | 0.9.0-beta.1; AAR + sample + reference deployment; TEST_DEBUG_KEY until signing secrets exist |
| 19 beta validation | BLOCKED | 7b05048 → c48221b | PR #20; CI 38674872520 (green) | NOT EXECUTED: no device reachable | Runbook + beta checklist run: NO_GO (31 blockers) |
| 28 review of 17–19 | CI_PASSED | 24b7a71 → ca9d6e7 | PR #21; CI 38759654224 | UNVERIFIED | Sprint "beta readiness without hardware"; 6 findings, 5 addressed |
| 29 privacy and retention | CI_PASSED | f98ec72 → 305837f | PR #22; CI 38761296858 | not needed | Retention sweep, erasure, data inventory |
| 30 phone-test readiness | CI_PASSED | df19d6d → dfed65a | PR #23; CI 38763660979 | not executed | Scanner lab record + import tool |

### Run 14 — Report coverage and result accuracy
- State: CI_PASSED (not DEVICE_VERIFIED; not merged)
- Started/completed: 14 October 2026 / 15 October 2026
- Exact base SHA: d4667c169a3f1fc2475be940390ec69429c92b06 (`run-13-native-integrity`, rechecked: PRs #1–#6 open drafts, `main` at f12746417fea301e2bb79761c3d61bc73848dcee)
- Head SHA: 3a50ab57e814f9071203537433dbe08717ff8743 (code; later commits on the branch update this log only)
- Branch / PR: `run-14-report-coverage` → base `run-13-native-integrity`; draft PR https://github.com/premiumcentraal-boop/Cyclone-scan/pull/8
- Changes delivered: see [RUN_14_REPORT_COVERAGE.md](RUN_14_REPORT_COVERAGE.md)
- Automated checks actually run:
  - Local (agent workspace, Python 3.13): `python -m pytest service/tests` → 303 passed (282 baseline + 21 new); `python testvectors/generate_risk_vectors.py` → 59 cases, vectors test green.
  - Local Android/Gradle: NOT RUN — the workspace cannot reach Google's Maven/SDK hosts. Android JVM tests, lint, assembly, native checks and the new cross-language step are verified only by the PR's CI.
- CI URL and outcome:
  - https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38645276924 (commit 6fc28b5): FAILED in "Test, lint and assemble". Raw job logs were not downloadable from the agent workspace, so the cause is inferred, not observed: the most likely failure was the clean-phone fake probe returning null settings (read as "could not read"), which the new completeness test rejects. 3a50ab5 fixed that and the next run passed; and CI now annotates Gradle/JUnit failures so future causes are visible without raw logs.
  - https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38645739610 (commit 3a50ab5): SUCCESS — native host tests + 9 detector mutations; Python suite; SDK JVM tests, SDK lint, SDK release assembly; scanner JVM tests and release assembly; new "Kotlin signal reports pass the server validator" step; native ABI packaging check. APK artifact 11932377091 (debug-key signed test build).
- Physical device / OS / app version: none (UNVERIFIED)
- Observed results: CI only. No phone has run scanner 0.7.0.
- External dependencies: GitHub Actions for Android build evidence; an authorized test phone for smoke testing coverage on real hardware.
- Remaining issues / limitations: see run notes "Limits".
- Next run and verified base: Run 15 (`run-15-verifier-compatibility`) from 63fd3bd.
- Owner decision 15 October 2026: "release" = mark PR #8 ready for review (not merged, no public release). Done.

### Run 15 — Verifier compatibility and reference fixtures
- State: CI_PASSED (not DEVICE_VERIFIED; not merged)
- Started/completed: 15 October 2026 / 15 October 2026
- Exact base SHA: 63fd3bdaf47286359db4c005f4cce0372292e594 (`run-14-report-coverage`, PR #8 open, ready for review)
- Head SHA: 3d68781ea0a434d334bb37677612e5c2c959e2b6 (code; later commits update this log only)
- Branch / PR: `run-15-verifier-compatibility` → base `run-14-report-coverage`; draft PR https://github.com/premiumcentraal-boop/Cyclone-scan/pull/14
- Changes delivered: see [RUN_15_VERIFIER_COMPATIBILITY.md](RUN_15_VERIFIER_COMPATIBILITY.md)
- Automated checks actually run:
  - Local Python 3.13: `python -m pytest service/tests` → 335 passed (303 + 32 new); risk vectors 60; attestation vectors 14.
  - Reproduced first: public Sony factory chain as of 2026-10-14 → `CERT_EXPIRED` before the change, passes after with `LEGACY_FACTORY_VALIDITY_EXEMPT`.
  - Local Android/Gradle: NOT RUN (Google Maven unreachable from the workspace); verified by PR CI only.
- CI URL and outcome: https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38648998069 — SUCCESS (native host tests + mutations; Python; SDK and scanner JVM tests incl. AttestationVectorsTest; lint; release builds; cross-language signal step; ABI check). APK artifact 11933204744 (debug-key test build).
- Physical device / OS / app version: none (UNVERIFIED)
- Observed results: CI only.
- External dependencies: none for this run; real-device chains (Run 19) would confirm OEM chain shapes.
- Remaining issues / limitations: see run notes "Limits".
- Next run and verified base: Run 16 (`run-16-device-lifecycle`) from the Run 15 head, after owner review.

## Repository note (15 October 2026)

A separate stack of draft PRs from the owner's account branches from Run 13 in parallel with this delegation: #7 Run 20 (`run-20-protocol-assurance`) → #9 Run 21 → #10 Run 22 → #11 Run 23 → #12 Run 24 → #13 Run 25 (`run-25-beta-evidence-gate`), opened 14 October 22:06–22:18 UTC. This delegation has not read, changed or rebased those branches. Both stacks modify code from the same Run 13 base, so the owner needs to choose an integration order before merging; topics may overlap with Runs 16–19 (e.g. protocol assurance, evidence history, lab evidence).

### Run 15b — Integrate Runs 20–25
- State: CI_PASSED — https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38650877770 (all jobs incl. new enrollment-transcript step)
- Inputs: Run 15 head 69e3bc591c4a9a94da3855c388ad87cbefd1fb70 + `run-25-beta-evidence-gate` 2cd8d99936a9b7c11a96c1b157342c10fb670757 (contains Runs 20–24). Agreement: Codex reply on PR #14 (15 October 2026); one merge commit, ancestry preserved, neither original stack force-updated, not for merge to main.
- Conflicts resolved: `attestation.py` (keep both evidence fields `verified_boot_hash` and `legacy_validity_exemption`), `reasons.py` (keep both code groups), `tests/test_api.py` (warnings now `ATTESTATION_CHAIN_UNRECOGNIZED`, `ENROLLMENT_LEGACY_UNBOUND`, `PLAY_INTEGRITY_UNAVAILABLE`). CI keeps every step from both stacks.
- Integration additions: SDK test `EnrollmentCoverageFixtureTest` writes maximum-size Run 20 transcripts carrying full Run 14 coverage (detected and all-unavailable, with nulls); CI checks them with the server's strict parser, transcript field set and signal validator (`tools/check_enrollment_fixtures.py`). History snapshots gain additive v1 metadata `verifier_ruleset` and `legacy_validity_exemption` (missing in older snapshots = unknown).
- Checks run locally: 390 Python tests passed; risk (60) and attestation (14) vectors unchanged. Simulated max transcript: 6.7 KiB of 32 KiB.
- Build-status note: this log is authoritative; Runs 20–25 scope and handoff live in [assurance/BUILD_STATUS.md](assurance/BUILD_STATUS.md).

### Run 16 — Enrollment and device lifecycle
- State: CI_PASSED (not DEVICE_VERIFIED; not merged)
- Started/completed: 15 October 2026 / 15 October 2026
- Exact base SHA: 04996b51fc7f691e43e3412f1ce7b7abb6a5bac9 (`run-15b-integrate-20-25`, PR #15)
- Head SHA: e042e7d1a2e0c62a618bb5f3bf731658792f9c73 (code)
- Branch / PR: `run-16-device-lifecycle` → base `run-15b-integrate-20-25`; draft PR https://github.com/premiumcentraal-boop/Cyclone-scan/pull/17
- Changes delivered: see [RUN_16_DEVICE_LIFECYCLE.md](RUN_16_DEVICE_LIFECYCLE.md)
- Automated checks actually run: local Python 3.13 `python -m pytest service/tests` → 408 passed (390 + 18 new); vectors unchanged. Android: PR CI only.
- CI URL and outcome: https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38652134596 — SUCCESS (native, Python, Android tests/lint/builds, cross-language signal and enrollment-transcript steps, ABI check, manifest).
- Physical device / OS / app version: none (UNVERIFIED)
- Migration implications: user_version 0 databases (Phase 1, Run 13, Run 22) are adopted and upgraded to 2 in place; STEP_UP enrollments now start pending (behaviour change, documented).
- External dependencies: the customer's authenticated backend must forward the gateway principal for ownership; none for tests.
- Next run and verified base: Run 17 (`run-17-verified-scan-history`) from the Run 16 head.

### Integration note — Run 26 merged (15 October 2026)
- `run-26-evidence-input-hardening` (PR #16, head c306521de76b8be506c77366a4354796b26e275e, CI green) merged into `run-16-device-lifecycle` as the agreed single follow-up. Scope: offline assurance tooling input hardening (`tools/assurance/*`, `evidence_json.py`), `test_assurance_adversarial.py`, `docs/assurance/RUN_26_EVIDENCE_INPUTS.md`. No conflicts.
- Local: 422 Python tests passed after the merge (408 + 14 from Run 26).

### Run 17 — Server-verified scan, refresh, key continuity and history
- State: CI_PASSED (not DEVICE_VERIFIED; not merged)
- Head SHA: 07039e11c58e3eeecb7c86b699a4731ae54670b4 (code; later commits update this log only)
- Started/completed: 15 October 2026
- Agent: Claude (implementation/integration role, taking over from the outgoing agent per the 15 October handoff)
- Exact base SHA: 78f8c7bedc62cbee5780146f15807044cdb66968 (`run-16-device-lifecycle`, PR #17).
  - Rechecked live before branching: the head was unchanged, all 17 PRs were open, and no Run 17, 18, 19 or 27 branch or PR existed.
- Branch / PR: `run-17-verified-scan-history` → base `run-16-device-lifecycle`; draft PR https://github.com/premiumcentraal-boop/Cyclone-scan/pull/18
- Plan and protocol written first: [RUN_17_VERIFIED_SCAN_HISTORY.md](RUN_17_VERIFIED_SCAN_HISTORY.md)
- Changes delivered: see the "Delivered" section of the run notes.
- Automated checks actually run locally (Python 3.13, OpenJDK 21, Android SDK 35 / NDK 27.2.12479018 / CMake 3.22.1 installed in the agent container):
  - `python -m pytest -q service/tests` → 488 passed (422 + 66 new in `test_verified_scan.py`).
    - Run 16 migration tests now assert `SCHEMA_VERSION` (3) instead of the literal 2; their intent ("upgraded to the current schema") is unchanged.
  - The full Gradle CI command (`:devicetrust:testDebugUnitTest :devicetrust:lintRelease :devicetrust:assembleRelease :scanner:testReleaseUnitTest :scanner:assembleRelease`) → BUILD SUCCESSFUL.
    - This is the first time this log records a *local* Android pass. Earlier runs could not reach Google Maven.
    - The first local attempt hit HTTP 429 from Maven Central; a retry succeeded.
  - Native host ctest (3/3) and all nine detector mutations rejected.
  - Signal, enrollment-transcript and new scan/rotation-transcript fixture checks pass.
  - `check_native_apk.py` passes.
  - Local JDK is 21, whereas CI uses 17, so CI remains the reference.
- CI URL and outcome: https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38667401633 (commit 07039e1) — SUCCESS: native host tests + mutations, Python, Android tests/lint/builds, signal, enrollment-transcript and new scan/rotation-transcript steps, ABI check, manifest. APK artifact 11943311095 (debug-key test build; PR CI builds the synthetic merge revision).
- Physical device / OS / app version: none (UNVERIFIED). Live Google Play Integrity decoding: not exercised; tests use fake decoders.
- Migration implications:
  - user_version 2 → 3 adds `retired_keys` and the `assurance_snapshots.source` column. Older snapshots are kept and read as legacy enrollment snapshots.
  - Scanner 0.7.0/4 → 0.8.0/5.
  - API version label 0.5.0 → 0.6.0.
- External dependencies:
  - Google Cloud project, Play Console linking and service-account credentials for live Play verdicts.
  - An authorized test phone.
- Coordination:
  - Native code is untouched; it is the Run 27 native-review area. No Run 27 PR existed at start.
  - Run 26 was not re-merged.
- Next run and verified base: Run 18 (`run-18-beta-packaging`) from the Run 17 head.

### Run 18 — Beta packaging and reference deployment
- State: CI_PASSED on b28db16 (not DEVICE_VERIFIED; not merged; not published)
- Started/completed: 15 October 2026
- Exact base SHA: 165d63905cb73f6349cad1a13aa046b4f0dc38d6 (`run-17-verified-scan-history`, PR #18, CI green on 07039e1; later commits are log-only)
- Branch / PR: `run-18-beta-packaging` → base `run-17-verified-scan-history` (stacked draft PR)
- Changes delivered: see [RUN_18_BETA_PACKAGING.md](RUN_18_BETA_PACKAGING.md), [DEPLOYMENT.md](DEPLOYMENT.md), [DEPENDENCY_LICENSES.md](DEPENDENCY_LICENSES.md)
- Automated checks actually run locally (agent container):
  - Python: 502 passed (488 + 14 new across `test_deployment.py` and `test_release_tools.py`).
  - The full Gradle CI command passed.
  - The AAR was published, and the separate `sample-integration` build compiled against it by coordinates.
  - The AAR is byte-identical after `--rerun-tasks` on this machine (sha256 9697bad8…).
  - `build_evidence` and `check_signing` ran against the real APK: TEST_DEBUG_KEY, signer 64abdca3….
  - Local process smoke test of `serve` + `serve-admin` on one database: 401 / 201 / 404 / 404 / 200 as the CI job asserts.
  - Docker: client only, no daemon in the container. The image build and container smoke test are verified only by the new CI job.
- CI URL and outcome: https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38673627448 (b28db16; tested merge revision 1c09dc3736d148acd2dc3c0cdc4ac2ec9a3fa964) — SUCCESS: native, Python, Android (incl. AAR rebuild/publish, sample build, build evidence) and the new reference-image job (image build, config check incl. placeholder failure, compose validation, client/admin container route separation).
  - CI candidate: scanner APK sha256 6e755729fcbe1a8130787b1c9487b6fb1dec7cadd606b6f3b7118bb94ddd3be6 (artifact 11945815509), AAR sha256 cfec9555f299d3be8f7377d454b60156963af269e707e57634e9188bbef5ebb7 (artifact 11945490721), `aar_reproducible: true` on the runner (JDK 17.0.20).
  - Finding: that run's build evidence recorded the signer as UNVERIFIED because the tool picked the runner's newest build-tools apksigner and hid its error. Verified separately with apksigner 35.0.0: signer d68e832fd99afbf2bfce8d052fe5e4587e83017cb9cb3b53f1aca0e2c1d66240, CN=Android Debug, i.e. TEST_DEBUG_KEY (the runner's own debug key, different from the local one). Fixed in the follow-up commit: CI passes build-tools 35.0.0 apksigner and the evidence keeps the error text.
- Physical device / live Google: none (UNVERIFIED).
- Signing: no approved identity configured; candidates are TEST_DEBUG_KEY. No key was generated.
- Open owner decisions: signing identity and secrets, project licence (Play Integrity dependency is proprietary), distribution channel, retention schedule.
- Follow-up 7b05048 (evidence fix): CI https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38674219916 — SUCCESS, signer now verified in CI (TEST_DEBUG_KEY a3be9322…); AAR digest identical to the previous run.
- Next run and verified base: Run 19 (device validation) from 7b05048.

### Run 19 — Device validation and beta candidate
- State: BLOCKED for physical validation. Delivered: connectivity record, operator runbook for the 17-case matrix, and an actual beta-checklist run → **NO_GO**. Not DEVICE_VERIFIED; nothing published.
- Date: 15 October 2026
- Exact base SHA: 7b05048 (`run-18-beta-packaging`, PR #19, CI 38674219916 green)
- Branch / PR: `run-19-device-validation` → base `run-18-beta-packaging`; draft PR https://github.com/premiumcentraal-boop/Cyclone-scan/pull/20
- Head SHA: c48221b; CI https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38674872520 — SUCCESS (all four jobs). CI success is not device validation.
- Connectivity, checked afresh:
  - no phone-gateway tool in this session
  - `adb devices`: none
  - no `/dev/kvm`, so no emulator
  - no Play/Cloud configuration
- Candidate:
  - CI run 38674219916, tested revision a3ad8978e2c736901d54a7f4c416bf3541a8e541
  - APK 008209744c920a80580b69182a2651ec0cffd547a29cbe4223305617beb91c61
  - AAR cfec9555… (reproducible across two CI runs)
  - TEST_DEBUG_KEY
- Checks actually run:
  - `tools.assurance.lab init` (empty lab)
  - `tools.assurance.beta_gate`: NO_GO, 31 blockers (docs/validation/beta-gate-result.json)
  - Python suite including the new `test_validation_record.py`
- Observations recorded: **none** (physical 0, emulator 0, synthetic 0).
- Unblock: an authorized reachable phone, a Play-recognized build with Cloud credentials, the owner's signing identity and licence decision, and coordination with the Run 27 native-review owner for the altered cases.

## Sprint: beta readiness without hardware (15 October 2026)

All six delegated runs (14–19) exist and are green. Run 19's beta gate is NO_GO with 31 blockers: 22 need phones, and the rest need the owner (Google Cloud/Play, signing identity, licence decision, threshold review, human approvals). This sprint closes what engineering can close without them. Run 27 is reserved for the other agent's native review.

- Run 28: independent review of Runs 17–19, with fixes.
- Run 29: privacy and retention.
- Run 30: phone-test readiness.

### Run 28 — Review of Runs 17–19
- State: CI_PASSED (not DEVICE_VERIFIED; not merged)
- Started/completed: 15 October 2026
- Exact base SHA: 24b7a715495942dec610172dc968e85b1b59369a (`run-19-device-validation`, PR #20; rechecked live: no newer commits or PRs)
- Branch / PR: `run-28-review-17-19` → base `run-19-device-validation`; draft PR https://github.com/premiumcentraal-boop/Cyclone-scan/pull/21 (head ca9d6e7, code)
- Changes delivered: see [RUN_28_REVIEW.md](RUN_28_REVIEW.md). F1 cross-phone key rotation refused; F2 contradicting scans step up and no longer become the history baseline; F3 rotation honours `require_play_integrity`; F4 client-IP requirement documented; F5 admin health check fixed; F6 recorded only.
- Automated checks actually run: local Python 3.13 → 515 passed. The new review module failed 8 of 10 on 24b7a71 before the fixes. Android: CI only.
- CI URL and outcome: https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38759654224 — SUCCESS (all jobs).
- Physical device: none (UNVERIFIED)
- Beta-gate approvals: unchanged. `protocol_review` and `integrated_claude_runs` stay UNVERIFIED; this report is input for the human reviewer, not a PASS.

### Run 29 — Privacy and retention
- State: CI_PASSED (not merged)
- Started/completed: 15 October 2026
- Exact base SHA: f98ec72 (`run-28-review-17-19`, PR #21)
- Branch / PR: `run-29-privacy-retention` → base `run-28-review-17-19`; draft PR https://github.com/premiumcentraal-boop/Cyclone-scan/pull/22 (head 305837f, code)
- Changes delivered: see [RUN_29_PRIVACY_RETENTION.md](RUN_29_PRIVACY_RETENTION.md) and [PRIVACY.md](PRIVACY.md)
- Automated checks actually run: local Python 3.13 → 530 passed (515 + 15 new).
- CI URL and outcome: https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38761296858 — SUCCESS (all jobs incl. reference image).
- Beta-gate approvals: `privacy_retention` stays UNVERIFIED until a human privacy review signs off.

### Run 30 — Phone-test readiness
- State: CI_PASSED (not merged; not device-tested)
- Started/completed: 15 October 2026
- Exact base SHA: df19d6d (`run-29-privacy-retention`, PR #22)
- Branch / PR: `run-30-phone-test-readiness` → base `run-29-privacy-retention`; draft PR https://github.com/premiumcentraal-boop/Cyclone-scan/pull/23 (head dfed65a, code)
- Changes delivered: see [RUN_30_PHONE_TEST_READINESS.md](RUN_30_PHONE_TEST_READINESS.md)
- Automated checks actually run: local Python 3.13 → 543 passed (530 + 13 new); CI import step simulated locally. Android: CI only.
- CI URL and outcome:
  - https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38763078952 (f9f2094): FAILED, scanner Kotlin compile. The new CI annotation step showed it directly: `Unresolved reference 'SCANNER_VERSION'` in Scanner.kt. Fixed in dfed65a.
  - https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38763660979 (dfed65a): SUCCESS (all jobs, incl. "Scanner lab record imports as a lab observation"). Scanner APK artifact 11987461178 (debug-key test build; not yet recorded as a candidate).
- Physical device: none. The next candidate build must come from this branch or later to use the lab-record button.

### Sprint result (15 October 2026)
- Runs 28–30 are CI_PASSED as stacked draft PRs #21 → #22 → #23 on #20. Nothing is merged or published.
- Beta gate: unchanged at NO_GO. This sprint produced inputs for `protocol_review`, `integrated_claude_runs` (RUN_28_REVIEW.md) and `privacy_retention` (PRIVACY.md), but those approvals need human sign-off. The 22 phone-dependent blockers now have a faster recording path (Run 30); they still need a phone.
- Owner decisions still open: test phone access, Google Cloud/Play setup, signing identity, licence, threshold review, merge order of PRs #1–#23 into `main`.
