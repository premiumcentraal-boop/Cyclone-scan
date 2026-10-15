# Dependency licences: Run 18 review

Status: **best-effort engineering inventory. This is not legal advice.** The owner must confirm it before promising open-source or commercial distribution.

- Inventory taken on 15 October 2026, from:
  - `:devicetrust` `releaseRuntimeClasspath`: 57 resolved coordinates
  - the installed Python service closure
- Licences are recorded as each project declares them. Confirm them against the exact versions you ship.

## Blocking owner decisions

1. **This repository has no licence file.** Until the owner chooses one, the code is "all rights reserved". Nobody may assume an open-source licence. The published POM therefore declares no licence.
2. **The Android SDK depends on proprietary Google libraries:**
   - `com.google.android.play:integrity`, `core-common`
   - `com.google.android.gms:play-services-basement`, `play-services-tasks`

   They are under the Android SDK / Play Core terms of service, not an open-source licence. The AAR does not bundle them; they are POM dependencies that each app resolves from Google's Maven. However:
   - The SDK cannot be described as "fully open source" with these dependencies.
   - A no-GMS / F-Droid build would need Play Integrity split into an optional module. This is not done.
3. **Google service terms** (Play Integrity API, attestation roots, revocation list) apply to every deployment. Quotas and terms are the operator's responsibility.

## Android SDK runtime (`com.devicetrust:devicetrust`)

| Group | Artifacts (resolved) | Declared licence |
|---|---|---|
| `org.jetbrains.kotlin` | kotlin-stdlib 2.1.0 | Apache-2.0 |
| `org.jetbrains.kotlinx` | kotlinx-coroutines-core/-android/-play-services 1.10.2 | Apache-2.0 |
| `org.jetbrains` | annotations 23.0.0 | Apache-2.0 |
| `androidx.*` | biometric 1.1.0, fragment, appcompat, core, lifecycle, activity, collection, … | Apache-2.0 |
| `com.google.android.play` | integrity 1.6.0, core-common 2.0.4 | **Proprietary** (Play Core SDK terms) |
| `com.google.android.gms` | play-services-basement 18.9.0, play-services-tasks 18.2.0 | **Proprietary** (Android SDK licence) |

- The SDK's own native library (`libdtnative.so`) is built from this repository's C sources and has no third-party native dependencies.
- **Test only:** JUnit 4.13.2 (EPL-1.0), kotlinx-coroutines-test (Apache-2.0) and org.json 20240303 (Public Domain; older releases used the "JSON License"). None of these ship in the AAR.

## Scanner APK (additionally)

- Jetpack Compose BOM 2024.12.01, Material 3, material-icons-extended: Apache-2.0.

## Python service (`device-trust-service`)

| Package (installed) | Declared licence |
|---|---|
| cryptography 50.0.1 | Apache-2.0 OR BSD-3-Clause |
| cffi 2.1.1 | MIT-0 |
| pycparser 3.0 | BSD-3-Clause |
| fastapi 0.143.1 | MIT |
| starlette 1.6.0 | BSD-3-Clause |
| pydantic 2.13.5 / pydantic-core 2.46.5 | MIT |
| annotated-types, annotated-doc, typing-inspection | MIT |
| anyio 4.15.1 | MIT |
| idna 3.20 | BSD-3-Clause |
| typing_extensions 4.16.0 | PSF-2.0 |
| opentelemetry-api 1.44.0 | Apache-2.0 |
| uvicorn 0.53.0, click 8.5.0 | BSD-3-Clause |
| h11 0.16.0 | MIT |

- `pyproject.toml` sets lower bounds only, so a deployment resolves newer versions. Pin with a lock or constraints file and re-run this review for the versions you ship.
- The reference deployment uses Caddy (Apache-2.0) and the `python:3.13-slim` image. Debian packages inside it carry their own licences.

## Bundled data

- `service/device_trust/trust_anchors/google_roots.json` and `android/scanner/src/main/assets/google_roots.json` hold Google's published attestation root certificates. They are public data, used as trust anchors.
- `*/fixtures/real/*`: real public attestation chains. See their `NOTICE.md` files.
