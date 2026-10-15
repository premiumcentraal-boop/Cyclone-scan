# Run 28 — Review of Runs 17–19

Base: `run-19-device-validation`, `24b7a715495942dec610172dc968e85b1b59369a` (PR #20).
Branch: `run-28-review-17-19`. Reviewer: Claude, the agent session that built Runs 14–16. Runs 17–19 were built by a different session, so this is a second look by a different context. It is **not** the independent human review that the beta gate's `protocol_review` and `integrated_claude_runs` approvals require, and this run does not mark either approval PASS.

## Scope

Reviewed in full:

- `scan_evidence.py`
- the Run 17 scan and key-rotation paths in `service.py`, `registry.py` (`rotate_key`, snapshots, `retired_keys`) and `evidence_history.py`
- the new API routes
- SDK `DeviceTrustClient.verifiedScan` / `rotateKeys`, `ScanEvidence.kt` and `ServerScanView.kt`
- the Run 18 reference deployment: `Dockerfile`, `compose.yaml`, `Caddyfile`, `policy.beta.json`, `DEPLOYMENT.md`
- the Run 19 validation records

Spot-checked: the Run 18 release tools (`build_evidence.py`, `check_signing.py`), the AAR/sample build wiring, and the migration to schema 3.

Not reviewed: native code (Run 27 owner), Codex's assurance tooling (Runs 23–26), and anything that needs a device or live Google services.

## Method

Each suspected defect was written as a failing test against the Run 19 head, run there, then fixed. The new test module `service/tests/test_review_run28.py` failed 8 of its 10 tests on `24b7a71`; the other 2 are controls for legitimate behaviour that must keep working. All 10 pass after the fixes.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| F1 | High | **Key rotation could move an enrolled identity to a different phone.** The enrolled key could authorise a new key attested on another phone (different attested model, different verified-boot key, or an older security patch) and the server answered ALLOW and rotated. Run 17 documents that rotation does not prove the same phone, but *contradicting* hardware evidence was not used at all. | Fixed: the new key's evidence is compared with the enrolled key's own attested evidence; any REVIEW finding refuses the rotation with `KEY_ROTATION_DEVICE_CHANGED` and changes nothing. Same-phone rotation, including after an OS update, still works. |
| F2 | High | **A scan whose fresh attestation came from another phone was "Server-verified · trusted",** and history compared each scan only with the latest snapshot, so one contradicting scan became the reference for the next one (a second scan from the other phone looked clean). | Fixed: scans compare with the enrolled key's evidence as well as the latest snapshot. With the new policy `scan_history_review: "step_up"` (the default, also set in `policy.beta.json`), a REVIEW finding gives STEP_UP with `SCAN_DEVICE_EVIDENCE_CHANGED`. `"report"` restores the Run 17 behaviour of listing the finding only. Legitimate OS updates are INFO findings and are unaffected. |
| F3 | Medium | **Key rotation ignored `require_play_integrity`.** Enrollment requires a Play verdict under that policy, but rotation registered a new key with none. The API had no token field, and the SDK never used its own `RequestHash.keyRotation`. | Fixed: optional `playIntegrityToken` on `/v1/key-rotations`, bound to `device-trust/key-rotation/v1` + transcript. The policy is enforced and the verdict feeds risk. The SDK sends the token when Play is configured. Tests cover a missing token and a token minted for another purpose. |
| F4 | Medium | **The reference deployment collapses every phone into one "network".** The fleet signals hash the client network. Behind the documented topology the service sees the backend's address unless the backend forwards `X-Forwarded-For` and Caddy's `trusted_proxies` matches the backend. Neither requirement was documented, and the `10.0.0.0/8` placeholder rarely matches Docker's published-port path. Under normal load the burst factors (40 and 30 points) would then raise every user's score. | Documented in `DEPLOYMENT.md`: the backend requirement, how to verify it, and a fallback of zeroing the two network weights. The Caddyfile line is marked as a placeholder. No code change; a startup check is not possible because the service cannot tell a backend address from a phone's. |
| F5 | Low | The `trust-admin` container inherits the image health check, which probes port 8080, while it listens on 8081, so it would always report unhealthy. | Fixed in `compose.yaml`. |
| F6 | Low | The SDK label for a STEP_UP scan with complete evidence is `VERIFIED_FRESH`. The scanner's wording is correct ("Server-verified · needs extra verification", caution tone), but the enum name could mislead an integrator who maps labels to UI. | Not changed; renaming a public enum is an API change. Recorded for Run 18's SDK documentation. |

Checked and found sound: transcript strictness (exact field sets, duplicate keys, size and depth); purpose and domain separation for challenges, Play hashes and signatures; challenge burn-before-check; owner scoping and tenant isolation on the new routes; ephemeral fresh keys never registered and never counted as enrollments; reuse of enrolled or retired keys as "fresh" evidence refused; the rotation compare-and-swap and retired-key uniqueness; snapshot minimality (no reported fields, signals or tokens); migration 3 adopting earlier databases; the separation of the admin and client processes; a non-root image user; and no secrets in the image or repository.

## Compatibility

- New reason codes: `KEY_ROTATION_DEVICE_CHANGED` (hard) and `SCAN_DEVICE_EVIDENCE_CHANGED` (step-up). New policy key: `scan_history_review`. New optional API and SDK field: `playIntegrityToken` on key rotation. No response fields changed, so older SDKs parse every response.
- Behaviour change vs Run 17: scans with REVIEW history findings now return STEP_UP by default. This narrows the earlier agreement that history codes are diagnostics only, using the "explicit policy" option the Runs 20–26 agent allowed for. One existing Run 17 test was updated to assert both policy modes.

## Results

- Python: 515 passed locally (504 + 10 new + 1 updated-mode test).
- Reproduction: the new module failed 8 of 10 on `24b7a71` before the fixes.
- Android: SDK test added for the rotation Play token; verified by CI only (Google Maven is not reachable from this workspace).
- Physical device and live Google: UNVERIFIED.
