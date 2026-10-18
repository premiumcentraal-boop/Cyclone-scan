# Handoff: test Cyclone Scan on a USB-connected phone and find bugs and improvements

For an agent (e.g. Claude Code) running **on the owner's PC with an Android phone connected over USB**, written 18 October 2026.

**Goal:**
1. Run the published development build on a real phone.
2. Exercise every feature.
3. Collect evidence: report files, logs, screenshots and timings.
4. Produce a prioritised list of bugs and improvements, and fix what is clearly fixable.

Nothing in this repository has been run on a physical phone before. Everything below that says "expected" comes from code and unit tests, not from observation.

## 0. Rules (read first)

**The phone:**
- It is the owner's **everyday phone** unless the owner says otherwise.
- **Never** root it, unlock the bootloader, install Magisk, Frida or LSPosed, flash anything, or factory-reset.
- Only change settings you change back (airplane mode, VPN, TalkBack, screen cast), and restore them at the end.
- Do not install other apps without asking.

**Privacy:**
- Never copy IMEI, serial numbers (including the serial shown by `adb devices`), phone numbers, accounts, contacts, photos, messages or OTPs into the repo, issues or chat.
- Use an anonymous alias for the phone, e.g. `phone-a`.
- Report files are already free of identifiers. Before committing logcat output, cut it to the app's own lines and remove anything personal.

**Repository:**
- Work on branches from `run-19b-dev-open-source`, the integration branch, and open PRs **into** it.
- **Never merge** without the owner's explicit "merge" or "merge and publish".
- **Never bump `cyclone.version`** in `android/gradle.properties` and never touch `docs/releases/**` unless the owner asks for a release. A push to the integration branch that changes those publishes a GitHub pre-release automatically.
- Do not rewrite history on shared branches. Do not touch `android/devicetrust/src/main/cpp`: native code belongs to the separate Run 27 native review; report native findings instead.

**Honesty:** record what you actually observed. A check that could not run is "not tested", never "passed".

## 1. What you are testing

| | |
|---|---|
| Repo | https://github.com/premiumcentraal-boop/Cyclone-scan (Apache-2.0) |
| Integration branch | `run-19b-dev-open-source` |
| Build under test | Pre-release **v0.9.0-dev.2**: https://github.com/premiumcentraal-boop/Cyclone-scan/releases/tag/v0.9.0-dev.2 |
| APK | `cyclone-scanner-0.9.0-dev.2.apk`, SHA-256 `1b93abd13976a7e03ce574e91fb7bdea663cf2d5bc0146772157b7f26af9f4d6` |
| Package | `com.devicetrust.scanner`, versionName `0.9.0-dev.2`, versionCode 7 |
| Signer | public DEV key, certificate SHA-256 `412b9e05c1418d4e5e1e0f86ee21687569b4623231f951e5cf6a8e67cc469416` |
| Built from | `fc63431dbb8770c218a38691b4f61a952b98f3ad` (the tag commit) |

The app has three tabs:
- **Scan:** a local diagnostic. It creates an attested hardware key, verifies it on the phone, runs root, hook, emulator and scam checks plus native checks, and gives a local score. It ends with **Save report file** and **Share report file**.
- **Biometric:** creates a biometric-bound key and signs a test payment after the biometric prompt.
- **Server:** the full flow against a verification server you run on the PC:
  - enrollment, signed login and biometric payment
  - **Run server-verified scan** (fresh attestation and history)
  - **Rotate enrolled keys**
  - **Share lab record**
  - **Save/Share report file**

Background documents:
- `docs/RUN_31_SCANNER_DEBUG_REPORT.md`: the report file format
- `docs/RUN_17_VERIFIED_SCAN_HISTORY.md`: the server scan
- `docs/RUN_19_DEVICE_VALIDATION.md`: the full 17-case lab matrix
- `docs/RUN_30_PHONE_TEST_READINESS.md`: lab records

## 2. Set up the PC

```sh
git clone https://github.com/premiumcentraal-boop/Cyclone-scan && cd Cyclone-scan
git checkout run-19b-dev-open-source
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
python -m pip install -e 'service[test]'
python -m pytest -q service/tests                  # sanity check; expect all to pass
adb devices                                        # phone listed as "device"; do NOT paste the serial anywhere
```

Download and verify the build:

```sh
mkdir -p device-test && cd device-test
gh release download v0.9.0-dev.2 --repo premiumcentraal-boop/Cyclone-scan   # or download from the release page
sha256sum -c SHA256SUMS
apksigner verify --print-certs cyclone-scanner-0.9.0-dev.2.apk | grep SHA-256   # expect 412b9e05…
cd ..
```

Record the phone facts. These are fine to keep, because they identify no person:

```sh
adb shell getprop ro.product.manufacturer; adb shell getprop ro.product.model
adb shell getprop ro.build.version.release; adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.security_patch; adb shell getprop ro.product.cpu.abilist
```

Install. If an older Cyclone build is installed with a different signer, uninstall it first.

```sh
adb install -r device-test/cyclone-scanner-0.9.0-dev.2.apk || { adb uninstall com.devicetrust.scanner; adb install device-test/cyclone-scanner-0.9.0-dev.2.apk; }
adb shell dumpsys package com.devicetrust.scanner | grep -E "versionName|versionCode"
```

## 3. Run the verification server on the PC

Use a dev policy that trusts the public dev key. It is a dev policy only and never for production.

```sh
cat > device-test/policy.dev.json <<'EOF'
{
  "package_name": "com.devicetrust.scanner",
  "signing_cert_sha256": ["412b9e05c1418d4e5e1e0f86ee21687569b4623231f951e5cf6a8e67cc469416"],
  "policy_version": "device-test-1",
  "allowed_action_types": ["login", "payment"],
  "confirm_key_required_actions": ["payment"],
  "risk": {"trusted_installers": ["com.android.vending", "com.google.android.packageinstaller"]}
}
EOF
device-trust check-config --policy device-test/policy.dev.json --profile dev    # WARNs are expected for dev
device-trust serve --policy device-test/policy.dev.json --db device-test/devices.sqlite \
  --host 127.0.0.1 --port 8080 --expose-reasons 2>&1 | tee device-test/server.log
```

- The server downloads Google's revocation list at start, so the PC needs internet.
- If the server refuses to start, that is a finding.

Tunnel the phone to the PC so no Wi-Fi setup is needed:

```sh
adb reverse tcp:8080 tcp:8080
```

In the app, Server tab → Server URL `http://127.0.0.1:8080`.

Alternatively, the app's "Copy policy.json for this app" button gives the same policy. Pull it with `adb shell` clipboard tools if needed; it should match the file above, and a difference is a finding.

## 4. Capture evidence while testing

Start a log capture for each session:

```sh
adb logcat -c
adb logcat -v time > device-test/logcat-full.txt &        # stop it at the end (kill %1)
```

App-only logs and crashes:

```sh
adb logcat -d -v time --pid=$(adb shell pidof com.devicetrust.scanner) > device-test/logcat-app.txt
adb logcat -d -b crash > device-test/crash.txt
```

Screenshots: `adb exec-out screencap -p > device-test/<name>.png` (check them for personal data first).

Report files:
1. Tap **Save report file**, then choose **Downloads**.
2. Run `adb pull /sdcard/Download/ device-test/downloads/`, and keep the `cyclone-scan-report-*.json` files.
3. Check one with `python3 tools/check_debug_report.py device-test/downloads/cyclone-scan-report-*.json`.

Also test **Share report file**: share to any app (e.g. Gmail draft or Files) and check that a `.json` attachment arrives, not text.

Performance:
- Note the "Scan took … ms" value.
- Run `adb shell dumpsys meminfo com.devicetrust.scanner | head -20` after a scan.
- Watch for ANRs (`adb shell dumpsys activity anr` / `/data/anr` is not readable without root; use logcat).

## 5. Test plan

Do each step, then record the result in the findings table in §6.

**A. First launch and the Scan tab**
1. Launch and tap **Scan this phone**. Expect a verdict within about 15 s, with no crash or ANR. Note the duration.
2. Read every card:
   - verdict
   - **Verification coverage**
   - blocking findings
   - "Why this score"
   - hardware attestation
   - signal groups
   - "About this result"
   Look for wrong, confusing or truncated text, and anything shown as green that was not actually checked.
3. **Expected findings on this phone:** USB debugging and Developer options are on (you are using adb), so `env_adb` and `env_dev_options` show as detected. Installed from adb, not Play, so the installer is untrusted. Note anything else that is detected or unavailable, and whether that is plausible.
4. **Save report file** and **Share report file**, as in §4.
   - In the report, read `summary`, `notScanned` (every item), `errors` and `phases`.
   - For each `notScanned` item, decide whether it is expected on this phone (e.g. sandbox ACCESS_DENIED), or a bug: a check that should run but did not, a wrong reason, or a missing hint.
5. **Scan again** three times. Results should be stable and nothing should crash. Note any check that flips between runs.

**B. Offline and degraded conditions** (restore each afterwards)
1. Airplane mode on → scan. Expect: the revocation list is UNAVAILABLE, the `revocation_list` phase is FAILED with an error in the report, and the app does not crash.
2. VPN on (any VPN app already installed; do not install one without asking) → scan. Expect `env_vpn` detected, worth 5 points of information only.
3. TalkBack on → scan. Expect the accessibility finding, but not a block on that alone. Also check that the UI is usable with TalkBack: labels and focus order.
4. Cast or mirror the screen, if available → scan. Expect `env_external_display`.

**C. Biometric tab**
1. Run the test with a fingerprint or face enrolled. Expect the confirm key to be created, the prompt shown, and the signature verified.
2. Cancel the prompt. Expect a clean "cancelled" result, not a crash.
3. If no biometric is enrolled (ask the owner; do not change it otherwise), it should say so clearly.

**D. Server tab** (server running, `adb reverse` active)
1. **Run server test.** Expect:
   - enrollment ALLOW or STEP_UP, with reasons shown thanks to `--expose-reasons`
   - signed login ALLOW
   - biometric payment ALLOW with the confirm key, or STEP_UP without it
2. **Run server-verified scan** twice. Expect:
   - the label "Server-verified (partial)", because Play Integrity is not requested without a Cloud project
   - fresh attestation VERIFIED
   - a history comparison on the second run
3. **Rotate enrolled keys**, then run the verified scan again. Expect the history to show the rotation and new scans to succeed.
4. Stop the server, then run a verified scan. Expect "Not server-verified", **never** a verified label.
5. **Save report file** on the Server tab. It must include `server.lastVerifiedScan` and the steps.
6. **Share lab record.** Save the JSON and import it as in §7.
7. Check `server.log` for errors and tracebacks.

**E. Robustness and UX**
1. Rotate the phone during a scan and on each tab. State should survive, with no crash or duplicate runs.
2. Background the app during a scan, then return. Then kill it (`adb shell am kill com.devicetrust.scanner` while backgrounded) and relaunch.
3. Dark mode and light mode. The largest font size (Settings → Display) shows layout and truncation problems.
4. Back button behaviour, rapid double taps on buttons, and very slow network (optional: `adb shell cmd connectivity` is limited; skip if unavailable).
5. Fresh install over the previous build (`adb install -r`): it should update in place and keep the enrollment.

**F. Native checks**
- In the report, look at the `native_collector` phase and the `native_*` items.
- If they are UNSUPPORTED or UNREPORTED on a normal arm64 phone, that is a **bug to report**. Include the `errorMessage`.
- **Do not change native code**; report it for the Run 27 native review.

## 6. Record findings

Create `docs/device-tests/2026-10-<day>-<alias>/` (e.g. `2026-10-18-phone-a`) on a branch `device-test-<alias>` from `run-19b-dev-open-source`. Commit:
- `README.md`:
  - phone facts (§2, no serial)
  - APK SHA-256
  - server commit
  - date
  - which steps ran and which were skipped (and why)
- `findings.md`, one row per issue:

  | # | Severity (crash / wrong result / misleading UI / missing data / UX / perf) | Step | What you did | Expected | Actual | Evidence file | Suspected code (file:line) | Fixed in |
  |---|---|---|---|---|---|---|---|---|

- `reports/`: the report files (`cyclone-scan-report-*.json`, already identifier-free).
- `logs/`: **trimmed** app-only logcat and the crash buffer, plus the relevant `server.log` lines. Remove the device serial and anything personal.
- `screenshots/`: only screenshots with no personal data.

Severity guide:
- **Crash / ANR**, and any case where the app **shows a verified, green or pass state for something that did not run**: highest.
- **Wrong result:** a check reports the opposite of reality.
- **Missing data:** a report gap without a reason or hint.
- **Misleading or unclear UI.**
- **UX.**
- **Performance.**

## 7. Lab-matrix evidence (optional, for the beta checklist)

The checklist in `docs/validation/` is NO_GO because no phone observations exist. Server-tab lab records can become observations, **but only for the exact candidate APK**, so make a candidate file for v0.9.0-dev.2:

```sh
python3 - <<'EOF'
import json
e = json.load(open("device-test/build-evidence.json"))
json.dump({"tested_revision": e["tested_revision"],
           "scanner_apk_sha256": e["artifacts"]["scanner_apk"]["sha256"]},
          open("device-test/candidate-dev2.json", "w"), indent=2)
EOF
python -m tools.assurance.lab_import device-test/lab-record.json --candidate device-test/candidate-dev2.json \
  --case clean_pixel --alias phone-a --ground-truth CLEAN --expectation-met yes --operator-verified \
  --lab device-test/lab.json
```

- `--case`: pick the case that matches this phone. Options are `clean_pixel`, `clean_samsung`, `clean_tee`, `offline`, `vpn_legitimate`, `accessibility_legitimate`, `repeat_scan` and `biometric`. **Never use the altered cases** (rooted, unlocked, Frida and so on) on an everyday phone.
- **Operator declarations:** set `--expectation-met` and `--operator-verified` only after comparing the result with the expectation in `docs/RUN_19_DEVICE_VALIDATION.md`. The owner or tester is the operator; these are declarations, not proofs.
- **Where the files go:** commit `lab.json` and the lab records under the findings folder. Do not overwrite `docs/validation/lab.json`, which belongs to the older candidate.

## 8. Fix what is clearly fixable

For each finding with a clear cause:
1. Write a failing JVM or Python test first. Test locations:
   - scanner: `android/scanner/src/test/...`
   - SDK: `android/devicetrust/src/test/...`
   - service: `service/tests/...`
2. Fix it on a branch from `run-19b-dev-open-source`.
3. Run the same checks CI runs:
   ```sh
   python -m pytest -q service/tests
   cd android && ./gradlew --no-daemon --continue :devicetrust:testDebugUnitTest :devicetrust:lintRelease \
     :devicetrust:assembleRelease :scanner:testReleaseUnitTest :scanner:assembleRelease && cd ..
   python3 tools/check_debug_report.py android/scanner/build/debug-report-sample.json
   ```
4. Install your local build and **re-test the finding on the phone** with `adb install -r android/scanner/build/outputs/apk/release/scanner-release.apk`. It is signed with the same dev key, so it updates in place.
5. Open a PR into `run-19b-dev-open-source`. Link the finding rows, and say what was re-tested on the phone and what was not.

Do not fix by hiding:
- never weaken or skip a test
- never turn an UNAVAILABLE check into a pass
- never tune weights to make a hard failure pass

Larger design changes, and anything in native code, are written up as proposals in `findings.md`, not implemented.

## 9. Finish

- **Restore the phone:** airplane mode, VPN, TalkBack, casting, font size and dark mode back as they were. Stop the server, run `adb reverse --remove-all`, and stop the logcat capture.
- **Leave the app installed** unless the owner wants it removed (`adb uninstall com.devicetrust.scanner`).
- **Push** the findings branch and fix PRs. Post one comment on PR #24 that links them and summarises:
  - how many findings, by severity
  - how many were fixed
  - what was not tested
- **Tell the owner:**
  - the top problems found
  - what was fixed (PR links)
  - what needs their decision
  - that a new APK only appears after they say "merge and publish" on a PR that bumps the version
