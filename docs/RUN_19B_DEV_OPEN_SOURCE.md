# Run 19b — Open-source development stage

Owner instruction (15 October 2026): *"Make it open source for now and decide the best options for the rest; this is the dev APK stage."*
Base: `run-30-phone-test-readiness` (`aa1b0ce`, PR #23: the other session's Runs 28–30, stacked on Run 19). Branch: `run-19b-dev-open-source`.

This run records the decisions the agent made under that instruction and implements them. They are reversible: each one names how to change it later.

## Decisions

| Topic | Decision | Why | How to change later |
|---|---|---|---|
| Licence | **Apache-2.0** for the whole repository (`LICENSE`, `NOTICE`, POM, `pyproject.toml`) | Permissive with an explicit patent grant. It suits a free SDK with a commercial/hosted path, and is compatible with every dependency. The Google Play libraries stay separate, proprietary dependencies that are not bundled. | Relicensing contributions needs the contributors' agreement. Decide before outside contributions arrive. |
| Repository | Already public; no change | — | — |
| Version label | `0.9.0-dev.1` (service `0.9.0.dev1`), replacing `0.9.0-beta.1` | "Beta" overstated a build with no device validation | Bump `cyclone.version` in `android/gradle.properties` |
| Dev signing | One committed, **public** development key: `android/signing/cyclone-dev.jks`, certificate SHA-256 `412b9e05c1418d4e5e1e0f86ee21687569b4623231f951e5cf6a8e67cc469416` | Each CI runner previously signed with its own random debug key (two runs gave two signers). Testers could not update in place and the dev policy allowlist changed every build. Repository secrets cannot be set from the agent environment, and a secret key brings no security benefit at this stage. | Add the four `CYCLONE_RELEASE_*` secrets: they take precedence automatically. Rotating the dev key means replacing both files in one commit. |
| Dev key safety | `check_signing` reports `DEV_KEY` and refuses it unless `--allow-dev`. `check-config --profile beta` **fails** any policy that trusts it; the `dev` profile warns. | Anyone can sign a repackaged app with a public key | — |
| Distribution | Tag-triggered **GitHub pre-releases** (`v*-dev.*`, `.github/workflows/dev-release.yml`) with the scanner APK, the SDK Maven repository zip, build evidence and manifest. The tag must equal `v<cyclone.version>`. | Free, public, versioned, and next to the code. Clearly marked pre-release. No store listing or Maven Central until device validation and a production key exist. | Add a Maven Central or GitHub Packages publication and a Play internal-testing track at the beta stage |
| Retention | **Adopt Run 29** (PR #22): per-table periods validated against the risk windows, an interval sweep in `serve`, `device-trust purge`, and owner/admin erasure. No separate implementation. | Run 29 already closed this gap more completely; a second mechanism would conflict | Run 29's `retention_*` policy keys |

## Effects to know

- **Existing installs:** dev APKs installed from earlier CI artifacts (random debug keys) must be uninstalled once. From now on, dev builds update in place.
- **Development policy:** `signing_cert_sha256: ["412b9e05c1418d4e5e1e0f86ee21687569b4623231f951e5cf6a8e67cc469416"]`, used with `check-config --profile dev`. Never use it with the beta profile or in production.

## Still not done (unchanged)

- Physical-device and live-Google validation (Run 19: blocked, NO_GO).
- Production signing identity.
- Licence review by a lawyer.
