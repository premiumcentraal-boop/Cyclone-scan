# Handoff: publish GitHub pre-release v0.9.0-dev.1

Written 16 October 2026 by the Runs 17–19b agent session. The owner asked for this release ("make a real release to GitHub so I can download the APK") and asked for a handoff so another agent can finish it.

## Why this is a handoff

- **Blocked:** cloud agent sessions cannot create tags or releases. The GitHub proxy refuses release creation (`HTTP 403: Creating, editing, or deleting releases is not permitted for this session type`), tag pushes and the refs API. No setting lifts this.
- **Who can publish:** a session with the owner's own GitHub credentials (Claude Code on the owner's computer, or the owner in the GitHub UI).
- **Do not work around the restriction** from a cloud session, e.g. with a workflow whose only purpose is to publish for the agent.

## State to verify first

Recheck these live. Do not trust this file blindly.

```sh
git fetch origin run-19b-dev-open-source
git rev-parse origin/run-19b-dev-open-source        # expected 8057f6efce4c25f27fb1623785ef668cbb80a2fa or a later descendant
gh release list --repo premiumcentraal-boop/Cyclone-scan   # expected: no v0.9.0-dev.1 yet
git ls-remote --tags origin v0.9.0-dev.1            # expected: empty
```

- **Branch:** `run-19b-dev-open-source` (draft PR #24, stacked on the other session's Runs 28–30, PR #23 → #20 → … → #1). Nothing is merged to `main`. Do **not** merge as part of publishing.
- **CI:** green on 8057f6e and on 7a11ca6 ([run 38816190597](https://github.com/premiumcentraal-boop/Cyclone-scan/actions/runs/38816190597)).
- **Version:** `android/gradle.properties` holds `cyclone.version=0.9.0-dev.1` and `cyclone.versionCode=6`. The tag **must** be `v0.9.0-dev.1`; the workflow refuses any other.
- **Workflow:** `.github/workflows/dev-release.yml`, on that branch only. It triggers on a pushed tag `v*-dev.*` or on `release: published`, then:
  1. checks that the tag matches the version
  2. runs the SDK and scanner unit tests
  3. builds the scanner APK, signed with the public dev key, and publishes the SDK to a local Maven repository
  4. writes `build-evidence.json`, and verifies the signer with apksigner 35.0.0 against `android/signing/dev-signer.sha256`
  5. attaches `cyclone-scanner-0.9.0-dev.1.apk`, `devicetrust-maven-repo-0.9.0-dev.1.zip`, `build-evidence.json`, `scanner-assurance-manifest.json` and `SHA256SUMS`
  6. creates the release, or for one already made in the UI, marks it pre-release and uploads with `--clobber`
- **First run:** the workflow has never executed. Watch it, and fix it if it fails.
- **Release notes:** `docs/releases/v0.9.0-dev.1.md` on that branch.

## Publish: option A (recommended), push the tag

From a checkout with the owner's credentials:

```sh
git fetch origin run-19b-dev-open-source
git tag -a v0.9.0-dev.1 origin/run-19b-dev-open-source -m "Cyclone Scan 0.9.0-dev.1 (development build)"
git push origin v0.9.0-dev.1
```

The workflow creates the pre-release with the notes it generates and attaches the assets. Optionally, replace the notes afterwards with `docs/releases/v0.9.0-dev.1.md`:

```sh
gh release edit v0.9.0-dev.1 --repo premiumcentraal-boop/Cyclone-scan --notes-file docs/releases/v0.9.0-dev.1.md
```

## Publish: option B, GitHub UI

1. Open https://github.com/premiumcentraal-boop/Cyclone-scan/releases/new.
2. Tag `v0.9.0-dev.1`, "Create new tag on publish".
3. Target branch `run-19b-dev-open-source`.
4. Title `Cyclone Scan 0.9.0-dev.1 (development build)`.
5. Description: paste the contents of `docs/releases/v0.9.0-dev.1.md`.
6. Tick **Set as a pre-release**, then **Publish release**.

Both the tag push and `release: published` may fire. The workflow's concurrency group runs them one after the other, and `--clobber` keeps the assets consistent.

## Verify after publishing

```sh
gh run list --repo premiumcentraal-boop/Cyclone-scan --workflow "Dev pre-release" --limit 3
gh release view v0.9.0-dev.1 --repo premiumcentraal-boop/Cyclone-scan    # pre-release, 5 assets
gh release download v0.9.0-dev.1 --repo premiumcentraal-boop/Cyclone-scan --dir /tmp/rel && cd /tmp/rel
sha256sum -c SHA256SUMS
apksigner verify --print-certs cyclone-scanner-0.9.0-dev.1.apk | grep "SHA-256"
# expected signer: 412b9e05c1418d4e5e1e0f86ee21687569b4623231f951e5cf6a8e67cc469416 (public DEV key)
python3 -c "import json;e=json.load(open('build-evidence.json'));print(e['signing']['identity'], e['tested_revision'])"
# expected: DEV_KEY and the tag's commit
```

Notes on the results:
- The release APK's SHA-256 **will differ** from the copy sent to the owner in chat (`64df1160…ae05`, CI build of 7a11ca6). It is a fresh build; the signer must still be the DEV key.
- If `build_evidence` reports `aar_reproducible: null`, that is expected: the release job builds once.

## If the workflow fails

- **Tag/version mismatch:** the tag must equal `v` + `cyclone.version`.
- **apksigner path:** it uses `$ANDROID_HOME/build-tools/35.0.0/apksigner`, which `setup-android` installs.
- **Release already exists without assets:** re-run the failed job, or push a fix to `run-19b-dev-open-source` and re-run. `--clobber` makes the upload idempotent.
- **Deleting and recreating the tag:** only with the owner's say-so. A published tag may already have been downloaded.

## Afterwards

- Update `docs/BUILD_LOG.md` (Run 19b entry): release URL, workflow run, APK SHA-256, signer, `tested_revision`.
- Comment the release link on PR #24.

## Honest status (put this nowhere stronger than the release notes)

- **Development build**, Apache-2.0, signed with a **public** development key. Not for production.
- **Not validated on a physical device:** the Run 19 beta checklist is NO_GO with 31 blockers.
- **No live Google Play Integrity configuration.**
- No production signing key exists. Release secrets (`CYCLONE_RELEASE_*`) were never set; agents in cloud sessions cannot set them.
- Native code was not touched by Runs 17–19b; the Run 27 native review is still unclaimed.
