# Cyclone Scan — living build log

Delegation plan of 14 October 2026 (Runs 14–19). Update after every run. Never mark planned work complete before evidence exists.

Status vocabulary: PLANNED, IN_PROGRESS, IMPLEMENTED, CI_PASSED, DEVICE_VERIFIED, BLOCKED. CI_PASSED does not imply DEVICE_VERIFIED or release approval.

| Run | State | Base / head | PR / CI | Device evidence | Notes |
|---|---|---|---|---|---|
| 13 baseline | CI_PASSED | d4667c169a3f1fc2475be940390ec69429c92b06 | PR #6; CI 38482579680 | UNVERIFIED | Scanner 0.6.0; 282 Python tests; 58 vectors |
| 14 report coverage | CI_PASSED | d4667c1 → 3a50ab5 | PR #8; CI 38645739610 | UNVERIFIED | Scanner 0.7.0; 303 Python tests; 59 vectors |
| 15 verifier compatibility | PLANNED | Run 14 successor | Not created | Not executed | Official/public fixtures |
| 16 device lifecycle | PLANNED | Run 15 successor | Not created | Not executed | Pending/approval/ownership |
| 17 server scan/history | PLANNED | Run 16 successor | Not created | Not executed | External Google setup may be needed |
| 18 beta packaging | PLANNED | Run 17 successor | Not created | Not executed | Stable signing setup dependency |
| 19 beta validation | PLANNED | Run 18 successor | Not created | Not executed | Normal-device matrix |

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
  - https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38645276924 (commit 6fc28b5): FAILED in "Test, lint and assemble". Raw job logs were not downloadable from the agent workspace; the clean-phone fake probe returned null settings (read as "could not read"), which the new completeness test rejects. Fixed in 3a50ab5, and CI now annotates Gradle/JUnit failures so future causes are visible without raw logs.
  - https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38645739610 (commit 3a50ab5): SUCCESS — native host tests + 9 detector mutations; Python suite; SDK JVM tests, SDK lint, SDK release assembly; scanner JVM tests and release assembly; new "Kotlin signal reports pass the server validator" step; native ABI packaging check. APK artifact 11932377091 (debug-key signed test build).
- Physical device / OS / app version: none (UNVERIFIED)
- Observed results: CI only. No phone has run scanner 0.7.0.
- External dependencies: GitHub Actions for Android build evidence; an authorized test phone for smoke testing coverage on real hardware.
- Remaining issues / limitations: see run notes "Limits".
- Next run and verified base: Run 15 (`run-15-verifier-compatibility`) from the Run 14 branch head, after owner review.
