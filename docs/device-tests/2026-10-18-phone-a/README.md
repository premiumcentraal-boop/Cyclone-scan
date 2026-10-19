# On-device test record: phone-a (18–19 October 2026)

One physical phone, the owner's everyday device. Scanner 0.9.0-dev.2 was tested first, then 0.9.0-dev.3 (the local build of the fix branch) was installed over it and re-tested for the fixed items.

## Phone facts (no serial, IMEI or account data)
- Google Pixel 8 (shiba), Android 16, API 36, security patch 2026-05-05, arm64-v8a, StrongBox present.
- Bootloader UNLOCKED and Magisk root present (the owner's configuration). Verified boot UNVERIFIED.
- Screen lock: not set (the owner's choice; it changes the biometric result).
- NordVPN active during the tests. AnyDesk installed. Four accessibility services enabled.

## Builds
| Build | Source | APK SHA-256 | Signer |
|---|---|---|---|
| 0.9.0-dev.2 | release `v0.9.0-dev.2`, `cyclone-scanner-0.9.0-dev.2.apk` | `1b93abd13976a7e03ce574e91fb7bdea663cf2d5bc0146772157b7f26af9f4d6` (matches the published digest and the app's own report) | public dev key `412b9e05…` |
| 0.9.0-dev.3 (local) | built on the fix branch at commit `82a3b0f` plus the test-contract fix | `eefae30ebd0af8e88e17d0911d8188e97a74de355358963c8daeef20f4ad31b9` | public dev key `412b9e05…` |

The 0.9.0-dev.3 digest above is for the local build. The CI-built release APK on the release page will have its own digest, because the build is not byte-reproducible across machines. The released APK should be re-checked against the release's `SHA256SUMS` before this record is cited for it.

## Scope
- Local diagnostic: 8 distinct scans on 0.9.0-dev.2 and 2 scans on 0.9.0-dev.3.
- Server tab: enrollment against a dev server on the PC (`--expose-reasons`, port forwarded with `adb reverse`), verified scan without enrollment.
- Offline: airplane mode with a copy of the revocation list saved within 24 hours.
- Biometric: the confirm-key test once (no screen lock, so no prompt).

## Not tested, and why
- Play Integrity: no Google Cloud project number; the build is sideloaded.
- Official signer verification: the app compares only with its own attestation.
- Biometric payment: needs a screen lock and an enrolled fingerprint; the owner did not set one.
- Server login, payment and key rotation: enrollment was blocked (BOOTLOADER_UNLOCKED), as the runbook expects for this phone.
- VPN on/off: the owner's VPN was left as it was.
- Any device other than this one; the 17-case lab matrix (`docs/RUN_19_DEVICE_VALIDATION.md`) needs more hardware.

## Files
- `findings.md`: one row per issue, with status and the commit that addresses it.
- `reports/`: every scanner report saved from the phone during these tests. They contain no serial, IMEI, account data, server address or file paths.
