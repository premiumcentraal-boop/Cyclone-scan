# On-device test handoff: Cyclone Scan, Run 30 head

Status as of 18 October 2026. Branch `run-30-phone-test-readiness`, head `aa1b0ce` (PR #23, draft, not merged). Nothing has run on a physical phone. No observation exists. Any claim beyond what this page lists is unverified.

## 1. Short answer

- The software is built, and its CI is green on the head. The phone-side scanner, the lab-record export and the import tool all exist.
- The beta gate is `NO_GO` with 31 blockers, as committed in `docs/validation/beta-gate-result.json`. `docs/validation/lab.json` has 0 observations.
- A phone session can clear at most **22 blockers** (17 lab cases plus `pilot_sample`, `clean_intervention`, `altered_miss`, `latency_p95` and `no_observed_crashes`). It can also support 2 review declarations that cite device evidence (`attestation_compatibility`, `device_lifecycle`).
- The other **7** need decisions that no phone can make: `dependency_licenses`, `integrated_claude_runs`, `live_google_verification`, `policy_review`, `privacy_retention`, `protocol_review`, `stable_signing`.

## 2. How far and how good

| Claim | State | Evidence |
|---|---|---|
| Python service behaviour | Verified, this branch | Full suite passes locally (exit 0, re-run 18 Oct on `aa1b0ce`). CI job "Trust service (Python)" succeeded in run 38764518718. |
| Kotlin SDK and scanner build, JVM tests, lint | CI only | "Test, lint and assemble" succeeded in run 38764518718. Not runnable here: `dl.google.com` and Google Maven are unreachable from the workspace (no HTTP response). |
| Kotlin lab record → Python importer, server mode | Verified in CI | Step "Scanner lab record imports as a lab observation (Run 30)" succeeded in run 38764518718. |
| Lab record, local mode | Verified by hand, not in CI | A record shaped like the Kotlin output imported as `PARTIAL` when 2 checks were unavailable. A record from a different APK was refused (exit 2). CI never exercises this path. |
| Candidate APK | Identified, not hashed | Artifact `device-trust-scanner-apk`, id 11988116613, from run 38764518718. Blob downloads are forbidden from this workspace, so the SHA-256 has to be computed on the tester's side. |
| Behaviour on a phone | **Not verified** | No device reachable. |
| Live Google Play Integrity | **Not verified** | No Cloud project, service account or Play-recognised build configured. |
| Lab server running | **Not verified here** | Startup needs Google's revocation list, which this workspace can't reach. |

The candidate in `docs/validation/candidate.json` (APK `008209…`, run 38674219916) predates the lab-record button. A phone session that uses the faster path needs a candidate built from this branch or later.

## 3. Bugs and errors

**Fixed in this pass** (uncommitted on `run-30-phone-test-readiness`):

1. `tools/assurance/lab_import.py`: a missing local or server scan was reported as "must be an object", which misleads the operator. It now says `lab record has no server scan (...)`. Test added: `test_missing_scan_is_reported_as_missing`.
2. `HANDOFF.md` described Run 14 and a five-PR chain at `7352e67`. It now points to Run 30 and this page.
3. `docs/BUILD_LOG.md`: the Run 30 row cited only the older CI run. It now cites run 38764518718 and its artifact.
4. `docs/RUN_19_DEVICE_VALIDATION.md`: setup said to use the reference service without naming a policy. Corrected: see §4 step 4 and the notes there.

**Checked and correct** (so nobody repeats the work): the runbook's 17 cases match `tools/assurance/lab.py` exactly. Verdict names match across Kotlin and Python. `CoverageCounts.toJson()` emits all five keys that the importer reads. The committed gate result matches the committed inputs. `check-config` failing on placeholders is intended.

**Open, not fixed** (needs a decision or GitHub access):

- **Candidate pointer is stale.** `candidate.json` still names the 7b05048 APK. Replacing it needs the artifact hash and `build-evidence.json` from the chosen CI run.
- **Beta policy cannot start a lab server.** `serve` refuses it without `--gateway-token-file` (`cli.py` lines 60–61). Its placeholders also fail `check-config`. The lab uses a copy of the example policy instead.
- **Server startup needs internet.** `build_service` refreshes Google's revocation list. A laptop without outbound HTTPS to `android.googleapis.com` cannot start the server.
- **CI covers only server mode for the lab record.** Adding a local-mode sample means a Kotlin change, and I could not compile Kotlin here.
- **No Kotlin compile check from this workspace.** Only CI proves the Android code.

## 4. Pre-flight, before a phone is touched

1. **Pick the candidate.** Use artifact `device-trust-scanner-apk` (id 11988116613) from run 38764518718, or a fresh CI run on the head. On the phone, install the CI APK only. A local rebuild is a different APK and its observations do not count.
2. **Identify it.** Compute the APK's SHA-256. Get the tested revision and digests from `build-evidence.json` in the same run. It records the merge revision that PR CI built, not only the PR head.
3. **Get the signer digest.** Run `apksigner verify --print-certs <apk>` from Android build-tools. CI builds are signed with `TEST_DEBUG_KEY`, so this is a lab-only candidate. The previous candidate's signer was `a3be9322…`.
4. **Write a lab policy.** Copy `service/policy.example.json` to a lab file. Set `package_name` to `com.devicetrust.scanner` and `signing_cert_sha256` to `["<signer SHA-256>"]`. Then run `python -m device_trust.cli check-config --policy <lab file> --profile dev`. Nothing should fail; warnings must be understood.
5. **Start the lab server** on the laptop, reachable from the phone:

   ```sh
   python -m device_trust.cli serve --policy <lab file> --db lab.sqlite \
     --host <laptop LAN address> --port 8080 --expose-reasons
   ```

   Use `--expose-reasons`, because the importer needs the score and reasons. Do not use the beta policy here.
6. **Point the phone at it.** In the scanner's Server tab, set the URL to `http://<laptop LAN address>:8080`. The app's default is `http://192.168.1.10:8080`, which is a placeholder.
7. **Record the candidate.** Write a new file in `docs/validation/` with at least `tested_revision` (40 hex) and `scanner_apk_sha256` (64 hex), plus the CI run and artifact id as Run 19 did. The importer checks against this file.

## 5. Per case (17 cases, from `docs/RUN_19_DEVICE_VALIDATION.md`)

For each case, on an authorised device only:

1. **Scan tab**: run the local diagnostic.
2. **Server tab**: run the server test, then "Run server-verified scan" twice.
3. **Share lab record (JSON)**, and send the file to the laptop. The record has no serial, IMEI, account data, server address or free text.
4. Compare the result with the expectation for this case in the runbook. Only then choose the outcome. Never tune anything to make a result pass.
5. Import it:

   ```sh
   python -m tools.assurance.lab_import record.json --candidate docs/validation/<candidate file>.json \
     --case clean_pixel --alias pixel-a --ground-truth CLEAN \
     --expectation-met yes --operator-verified --lab docs/validation/lab.json
   ```

   Add `--operator-verified` only after you have reviewed the result. Add `--crashed` if the app crashed. Use `--mode local` only for the local diagnostic. For the `emulator` case, add `--origin EMULATOR` and declare it as such.

**Devices the matrix needs:** two locked stock phones (Pixel and Samsung), a TEE-only phone without StrongBox, a designated bootloader-unlocked unit, a rooted or hooked configuration, a custom ROM such as GrapheneOS, a device without Google services, and a declared emulator. Use one stable alias per phone. The `frida_inprocess` and `lsposed_inprocess` cases need coordination with the Run 27 native-review owner.

## 6. After the cases

- `python -m tools.assurance.lab report docs/validation/lab.json --revision <tested revision> --apk-sha256 <APK SHA-256>`
- `python -m tools.assurance.calibration docs/validation/lab.json --revision <…> --apk-sha256 <…>`
- `python -m tools.assurance.beta_gate docs/validation/lab.json docs/validation/beta-review.json`

Expect `NO_GO` until the human approvals in §1 exist. Do not edit the gate result by hand. Committing `lab.json` is a repo change, so do it on a branch and only with owner approval.

## 7. Stop and report if

- the app crashes, or a server result differs from the expectation (record the miss, do not remove it);
- the importer refuses a record (wrong APK, missing score or reasons);
- a screen or file shows an identifier or account detail.

## 8. What a phone session cannot establish

- Live Google verification, or a stable signing identity (CI builds use the debug key).
- Licence and privacy decisions, protocol review, or the integrated review of Claude runs.
- Behaviour on OEM models you did not test.
- Any accuracy or statistical claim. The pilot prerequisite is five clean and three altered aliases, which is a sample size, not a result.
- Authenticity of a lab record. It is unsigned, so the gate treats origin and review as declarations.

## 9. What to send back

The lab record JSON files, the candidate file used, the `lab.json` diff, and a short note of misses, crashes and refusals. Do not send account data, serial numbers or raw logs.
