# Run 31 — Downloadable scanner results and debug report

Owner request (16 October 2026): "Export a full report that is easily downloadable … also sharing what couldn't be scanned … a results / debug file export with full context to help developers fix and improve the scanner."
Base: `run-19b-dev-open-source` (`073251e`, after the v0.9.0-dev.1 release). Branch: `run-31-scanner-debug-report`.

## What changed

**Export as a file, not text.** The scanner's "Share diagnostic report (JSON)" button used to put JSON text into a share intent. It is replaced by:
- **Save report file:** Android's file picker (`ACTION_CREATE_DOCUMENT`), so the user can choose Downloads or Drive. Name: `cyclone-scan-report-<maker-model>-<UTC time>Z.json`.
- **Share report file:** a real `.json` attachment through a private `FileProvider` (`<package>.reports`, cache sub-directory only, read grant per share). Earlier exports are removed from the cache first.

The buttons appear:
- after a scan
- after a **failed** scan, which previously could not be exported at all
- in the Server tab, where the report also covers server and biometric results

**The report** (`cyclone-scan-debug-report`, schema 1; builder `scan/DebugReport.kt`, pure Kotlin):

| Section | Contents |
|---|---|
| `summary` | Local scan COMPLETED / FAILED / NOT_RUN, verdict, score, checks total / completed / detected / not scanned, hard failures, server label, biometric run |
| `notScanned` | One item per gap, with `kind`, `id`, `label`, `state`, `reason`, `explanation` and `developerHint`. See the list of kinds below. |
| `errors` | Where it failed, the exception class and a sanitized message (causes included) |
| `phases` | Each scan phase with its outcome (OK / FAILED / DEGRADED) and duration |
| `app` / `device` | Version and versionCode, APK SHA-256, installer, debuggable; maker/model, SDK, release, security patch, ABIs, StrongBox feature |
| `localScan` | The complete existing schema-2 report (signals, findings, coverage, attestation) |
| `server` / `biometric` | Latest verified scan, server steps with dev-server reasons and error; biometric checks |

The `notScanned` kinds are:
- `check`: Kotlin or native checks that are UNAVAILABLE, UNSUPPORTED or UNREPORTED
- `attestation_check`: UNVERIFIED attestation fields
- `comparison`: hardware-versus-reported comparisons with a missing side
- `layer`: verification layers that are UNAVAILABLE, PARTIAL or NOT_EVALUATED
- `phase`: failed or degraded scan phases
- `server` / `server_evidence`: no server verdict, or evidence that was not verified
- `biometric`: unverified biometric steps
- `scan`: the local scan itself failed

**Errors are no longer discarded.** Each scan phase now runs through a `ScanTrace`:
- **Hardware key generation:** the KeyStore exception is now recorded; it was previously swallowed.
- **Revocation download:** a new `ChainVerifier.fetchRevocationsResult` keeps the error.
- **Native collector:** the SDK's `JniNativeProbe.lastError` records library-load and collection failures. That is Kotlin glue only; no native C code changed (Run 27 area).
- **Results unchanged:** each probe returns exactly what it returned before.

**Privacy.**
- **No identifiers:** no serial number, IMEI, account data, server address or tokens. A test and a CI step reject such fields.
- **Sanitized messages:** error messages have file paths (two or more segments), URLs and long hex identifiers replaced, and are bounded to 240 characters.
- **Server steps:** the report carries the step title, decision and reason codes, not free-text details.

## Version

`0.9.0-dev.2` (versionCode 7). **Merging this run's PR into `run-19b-dev-open-source` publishes the pre-release `v0.9.0-dev.2`** through the release workflow, with notes in `docs/releases/v0.9.0-dev.2.md`. The sample app and the toolchain test now read the version from `android/gradle.properties`.

## Tests
- `scanner/src/test/.../DebugReportTest.kt` checks:
  - every gap kind is listed with its reason and hint
  - completed checks are not listed
  - summary counts are consistent
  - errors are kept but sanitized
  - a crashed scan still produces a report
  - server gaps are included
  - full context is present, with no identifier fields
  - the file name format
  - sanitizing leaves ordinary text such as "3/4" alone
- The test writes `scanner/build/debug-report-sample.json`. CI checks it with `tools/check_debug_report.py`: sections present, every item complete, no identifier fields, sanitized errors.

## Not verified
The file picker and share sheet were not exercised on a physical phone; no device is reachable from the agent environment. JVM tests cover the report content, and the APK manifest was checked for the provider.
