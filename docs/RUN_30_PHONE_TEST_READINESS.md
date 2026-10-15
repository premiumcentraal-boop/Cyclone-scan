# Run 30 — Phone-test readiness

Base: `run-29-privacy-retention` (PR #22). Branch: `run-30-phone-test-readiness`. Physical device: not available; this run makes the first phone session faster and less error-prone.

## Why

22 of Run 19's 31 beta-gate blockers need observations from real phones. The Run 19 runbook asks the operator to copy about a dozen values from the screen into a hand-written JSON observation for each of 17 cases. That is slow and makes transcription errors likely, and nothing checked that an observation came from the candidate APK.

## Delivered

- **Scanner: "Share lab record (JSON)"** (Server tab, "Lab record (testers)" card). It exports only measured facts, as `cyclone-scan-lab-record` v1:
  - the SHA-256 of the installed APK file itself
  - the app version and the OS
  - the local scan: verdict, score, hard-failure IDs, factor names, coverage counts, duration
  - the latest server-verified scan, with its measured duration: label, decision, evidence statuses, history change codes, coverage and, from a `--expose-reasons` server, reasons, score and factors

  It has no fields for the case, alias, ground truth or outcome, and includes no serial, IMEI, account data, server address or free text.
- **`python -m tools.assurance.lab_import`** turns a record plus the operator's declarations into a `tools/assurance/lab.py` observation. It validates the observation with the existing schema and appends it with `--lab`.
  - It refuses a record from an APK other than the candidate's, and a server result without score and reasons.
  - Mapping: VERIFIED evidence gives COMPLETE coverage, missing Play or fresh attestation gives PARTIAL, and an unavailable server gives INCOMPLETE/UNAVAILABLE. The local mode is PARTIAL whenever any check was not verified.
  - Only non-risk reasons count as a hard failure. The observation ID is derived from the alias, case and record digest, and `source_report_sha256` is the record's digest.
- **Scanner fix:** the shared report's `scanner` field now uses the installed `versionName`. The hard-coded constant had stayed at 0.7.0 through Runs 17–18.
- **CI:** a new step imports the Kotlin-produced sample record with the Python tool, so the two formats cannot drift apart.
- **Runbook:** the faster path is added to [RUN_19_DEVICE_VALIDATION.md](RUN_19_DEVICE_VALIDATION.md).

## Tests

- Python `test_lab_import.py` (13 tests):
  - mapping for server, partial, hard, risk-block, unavailable, local and crash results
  - refusals: wrong APK, missing score, unknown decision
  - the auto-mode fallback
  - the CLI appending to a lab file, then `lab.summary` reporting PASS
  - duplicate-key and emulator-origin refusals
  - operator fields in a record are ignored
- Kotlin `LabRecordTest`: measurements only and no identifiers, explicit unavailable and missing scans, the APK digest, and the CI sample.

## Limits

- The record is not signed. It does not authenticate that a phone produced it, and the gate keeps treating origins and reviews as operator declarations.
- The current candidate (0.9.0-beta.1, `008209…`) predates this button. Phone testing with the faster path needs a new candidate build from this branch or later, recorded in `docs/validation/candidate.json` the way Run 19 did.
