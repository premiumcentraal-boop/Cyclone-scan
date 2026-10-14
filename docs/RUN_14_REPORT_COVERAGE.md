# Run 14 — Report coverage and result accuracy

Base: `run-13-native-integrity`, `d4667c169a3f1fc2475be940390ec69429c92b06` (rechecked on 14 October 2026; PRs #1–#6 open drafts, `main` at Phase 1 `f127464`).
Branch: `run-14-report-coverage`. Scanner: 0.7.0 (versionCode 4). Physical device: UNVERIFIED.

## Problem

Older Kotlin checks collapsed every error into `false`/`null`. A denied `/proc` read, an inaccessible root path or a failed Android query was shown in the scanner as a green "not detected", and the server could not tell the difference either. A local result could also be read as if Google or server checks had run.

## Delivered

**SDK (`android/devicetrust`)**

- `Coverage.kt`: `CheckState` (DETECTED / NOT_DETECTED / UNAVAILABLE / UNSUPPORTED), a bounded `CheckReason` vocabulary (COMPLETED, ACCESS_DENIED, PARTIAL_COVERAGE, READ_ERROR, MALFORMED, TOO_LARGE, API_ERROR, API_UNSUPPORTED) and `ValueState` (COLLECTED / UNAVAILABLE / UNSUPPORTED) for reported values.
- Multi-source checks use the native collector's existing rule: one hit is DETECTED; NOT_DETECTED requires every source to complete; otherwise UNAVAILABLE (ACCESS_DENIED, or PARTIAL_COVERAGE when some sources completed).
- `SignalProbe` gains `pathState` and `readTextResult` with defaults, so existing probe implementations still compile. `AndroidSignalProbe` now separates ENOENT/ENOTDIR from EACCES via `Os.stat`, reports TOO_LARGE / MALFORMED / ACCESS_DENIED reads, and lets refused or failed Android queries surface instead of returning `false`. A refused loopback connection, `ClassNotFoundException`, `NameNotFoundException` and an unset global setting (platform default 0) remain completed answers.
- `DeviceSignals` emits `<key>_status` and `<key>_reason` for every Kotlin check, `env_a11y_third_party`, `env_remote_access_apps`, and the value fields (`app_installer`, `app_signature_sha256`, `os_security_patch`, `os_release`), plus `signal_coverage_version: 1`. "No installer recorded" (COLLECTED, null) is now distinct from "installer query failed" (UNAVAILABLE). A missing or garbled `TracerPid` line is MALFORMED instead of "not traced".
- No new detection methods, paths, permissions or privileges. Native code is unchanged; native comparison semantics are unchanged.

**Wire compatibility.** The report stays `"v": 1`. Booleans keep their meaning (`true` only for DETECTED), so old servers ignore the new keys and score identically. Old clients that send no states still parse; the server counts their checks as UNREPORTED rather than complete. An unknown `signal_coverage_version` or `v` is an explicit `SignalsError`.

**Service (`service/device_trust`)**

- `signals.py` validates the new fields strictly: allowed vocabularies; `true` ⇔ DETECTED; count > 0 / non-empty list ⇔ DETECTED; COMPLETED only on completed states; a reason requires a status; an UNAVAILABLE value must be null.
- `coverage_summary()` counts states. `RiskResult.coverage` and the API's `risk.coverage` expose the counts (additive response field). Coverage never changes scores or factors.
- Risk weights are unchanged. Shared vectors: one new case, `kotlin_checks_unavailable` (59 cases), proving identical scores; the file keeps its CRLF line endings.

**Scanner (`android/scanner`)**

- New `Check.Status.UNVERIFIED` (grey question mark). Rows for UNAVAILABLE / UNSUPPORTED / UNREPORTED checks say "could not verify: <reason> · not evidence of safety"; they are never green.
- "Keybox & spoofing" comparisons show "not compared" when attestation evidence or the reported value is missing (e.g. codename releases). The signature row no longer says "untampered" when nothing was compared, and states that a match is self-consistency, not official signer verification.
- New "Verification coverage" card: hardware attestation, revocation list, Kotlin and native check completion, and Play Integrity / server policy / fleet history / official signer explicitly NOT EVALUATED in local mode. The verdict card counts unverified checks and labels the score as risk points, not a probability.
- Export schema `cyclone-scan-report` version 2: keeps every 0.6.0 field and adds `findings` (id, source, state, reason), `coverage` counts, `verification` layers and an `exportNotice`. Attestation check detail is truncated to 120 characters. No paths, memory maps, serial/IMEI, account data or secrets are exported.

**CI.** A new step parses the Kotlin-produced detected and all-unavailable signal samples with the Python validator, so a schema drift between collector and server fails the build.

## Tests

- Python: `service/tests/test_signal_coverage.py` (compatibility, vocabulary, contradictions, score invariance, partial/unsupported states); `test_risk.py` updated for the additive `coverage` response field.
- SDK JVM: clean phone completes every check; denied reads are never clean; partial path coverage; detection survives an unreadable source; API failure classification; malformed TracerPid; installer/signature value states; any-of rules; wire coherence.
- Scanner JVM: `ReportCoverageTest` — denied checks never PASS, clean completed checks PASS, legacy reports are UNREPORTED, no-attestation comparisons are "not compared", codename release, installer states, local mode never claims server layers, export versioning/bounds/no paths.

Results are recorded in [BUILD_LOG.md](BUILD_LOG.md) from actual runs only.

## Limits

- Classification is only as good as what Android reports. `File`/`Os.stat` distinctions, `FileNotFoundException` causes and system-service failures were not observed on a physical phone in this run.
- Many fixed root paths are normally inaccessible to a sandboxed app, so on real phones several root checks will likely report UNAVAILABLE / PARTIAL_COVERAGE. That is the honest result, not a regression; device data (Run 19, or earlier smoke tests) should confirm typical coverage.
- A failed installer query still scores `app_installer_untrusted` and an unreadable signature still adds no mismatch factor — existing scoring preserved deliberately; the report now labels both.
- Client evidence remains low trust; a compromised phone can forge states as easily as booleans.
- The server scan flow does not yet display server coverage in the scanner's Server tab; that belongs with the Run 17 server scan.
