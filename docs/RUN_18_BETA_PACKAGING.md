# Run 18 — Beta packaging and reference deployment

Base: `run-17-verified-scan-history`, `165d63905cb73f6349cad1a13aa046b4f0dc38d6` (PR #18).
Branch: `run-18-beta-packaging`. This prepares a candidate **for review**: no publication, no approved signing identity, and no physical device evidence.

## Version

`0.9.0-beta.1`:
- SDK AAR `com.devicetrust:devicetrust:0.9.0-beta.1`
- scanner versionName `0.9.0-beta.1`, versionCode 6 (was 0.8.0 / 5 from Run 17)
- service `0.9.0b1`, the PEP 440 form of the same version; also the API version label

The values live in `android/gradle.properties` (`cyclone.version`, `cyclone.versionCode`).

## Deliverables

- **Consumable AAR:**
  - `maven-publish` on `:devicetrust` publishes the release AAR with its POM, Gradle module metadata, a sources jar and checksums. The command is `./gradlew :devicetrust:publishReleasePublicationToLocalBetaRepository`, and the output goes to `android/devicetrust/build/repo`.
  - Native libraries for arm64-v8a, armeabi-v7a and x86_64, and the consumer ProGuard rules, are inside the AAR.
  - CI uploads the repository as the `device-trust-sdk-maven-repo` artifact. Where it is hosted is an owner decision.
- **Sample integration:** `android/sample-integration` is a *separate Gradle build*. It depends on the SDK only by Maven coordinates from that repository, as a customer app would. It shows enroll → server-verified scan with the honest label → signed action. CI builds it (`./gradlew -p sample-integration :app:assembleDebug`).
- **Signing:**
  - The scanner release build takes the approved identity only from `CYCLONE_RELEASE_STORE_FILE` / `_STORE_PASSWORD` / `_KEY_ALIAS` / `_KEY_PASSWORD`. In CI these come from repository secrets; `CYCLONE_RELEASE_KEYSTORE_B64` is decoded to a temporary file.
  - Without them it remains a debug-key **test** build. `-Pcyclone.requireReleaseSigning=true` makes a missing identity a build failure.
  - No key was generated. **No release secrets exist in the repository today, so CI candidates are `TEST_DEBUG_KEY`.**
- **Signer vs allowlist:** `tools/release/check_signing.py` verifies the APK signature with `apksigner` and compares each signer with `signing_cert_sha256`. It rejects debug keys by default, and documents the Play App Signing case.
- **Build evidence:** `tools/release/build_evidence.py`, uploaded with the APK as `build-evidence.json`, records:
  - the tested revision
  - SHA-256 and size of the AAR, scanner APK and sample APK
  - the apksigner-verified signer digests and identity class
  - the toolchain (Gradle, AGP, Kotlin, compileSdk, NDK, CMake, JVM target, JDK)
  - whether a `--rerun-tasks` rebuild of the AAR on the same runner is byte-identical. A difference fails the step.

  The existing Run 25 `scanner-assurance-manifest.json` is unchanged and still produced.
- **Reference service:**
  - `service/Dockerfile`: non-root, a `/data` volume and a health check.
  - `deploy/reference/`: beta policy, compose topology, Caddy TLS proxy.
  - `device-trust serve-admin`: the admin-only API on a separate internal listener.
  - `device-trust check-config`: an offline beta-profile check that never prints secrets.
  - SQLite WAL mode for the shared file.
  - Admin and gateway tokens must differ.
  - A CI job builds the image, runs the config check (the shipped placeholder policy must fail), validates the compose file, starts the client and admin containers, and asserts route separation and gateway authentication.
- **Docs:**
  - [DEPLOYMENT.md](DEPLOYMENT.md): TLS, gateway authentication, admin separation, storage/backup/retention, logs, dependencies.
  - [DEPENDENCY_LICENSES.md](DEPENDENCY_LICENSES.md).

## Behaviour changes

- `create_app(..., public=False)` builds an admin-only app. `public=True` is the default and is unchanged.
- `serve` refuses identical admin and gateway tokens.
- File-backed registries switch to WAL journal mode and a 10 s busy timeout.

## Owner decisions still open (block distribution)

1. The approved signing identity: create it in your key-management process and add the four secrets. Choose between Play App Signing and direct distribution, and set the service allowlist to match.
2. A project licence. The SDK's Play Integrity dependency is proprietary; see the licence review.
3. Distribution channel for the AAR and the APK.
4. Retention schedule for decisions, lifecycle and fleet events (not automated).

## Not done here

- Live Google Play Integrity and physical devices: Run 19.
- High availability (in-memory challenge store).
- Pinning the image base by digest.
- Pinning Python dependency versions.
