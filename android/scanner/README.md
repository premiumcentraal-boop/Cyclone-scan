# Device Trust Scanner (test APK)

A standalone Android app that runs the device-trust engine on the phone it is
installed on and shows the verdict. It is the demo and field-test tool for the
engine, not the production integration.

## Tabs

**Scan** (no server needed)
1. Creates a throwaway hardware-backed key with a random challenge.
2. Verifies its attestation chain on the phone: Google roots (RSA + 2025 EC CA),
   chain signatures, leaf-only extension, live Google revocation list,
   security level, StrongBox, bootloader lock, verified boot, key origin,
   app identity, patch age, hardware-attested model vs reported model.
3. Collects the SDK's RASP signals (root, hooking, debugging, emulator, app
   integrity, scam/remote-control, device settings).
4. Scores them with the same weights and thresholds as the server
   (parity enforced by `testvectors/risk_vectors.json`). Any hard attestation
   failure forces BLOCK.
5. Shows ALLOW / STEP_UP / BLOCK, the score, every contributing factor and
   each individual check. **Share report** exports privacy-safe JSON (no
   serial, IMEI or accounts) — collect these from many phones to calibrate.

The scan also shows a **Keybox & spoofing** group: whether the attestation
key was provisioned by Google (RKP) or comes from a factory keybox, whether a
factory keybox appears on a phone that only uses RKP (the TrickyStore
pattern), and whether the security patch and Android version the OS reports
match what the hardware attests (property spoofing).

**Biometric** — creates a biometric-bound confirm key, shows what the
hardware attests about it (strong biometric only, auth for every signature),
then asks you to approve a €1.00 test payment and verifies the signature.

**Server** — the production flow against a running Device Trust Service:
enrollment, a signed login and a biometric-confirmed payment, with the
server's decisions, reasons and risk breakdown. On a computer on the same
Wi-Fi:

```bash
python -m pip install -e 'service[test]'
# In the app: Server tab → "Copy policy.json for this app", save it as policy.json
device-trust serve --policy policy.json --host 0.0.0.0 --expose-reasons
```

then enter `http://<computer-ip>:8080` in the app.

**Server-verified scan** (Run 17, Server tab, after the server test has enrolled
the phone): the server checks the phone now. It uses a fresh hardware
attestation for a one-time challenge, signed by the enrolled key. The result
shows:
- the verdict, verification time and the time the result may be shown until
- the policy label and digest
- what was verified: signature, fresh attestation, Play Integrity, client checks
- how this evidence compares with the previous verified evidence

Results are labelled server-verified, partial (e.g. no Play verdict because no
Cloud project number was entered), expired, rejected, or not server-verified.
A failed or unreachable server is never shown as verified. The Scan tab is
always a *local diagnostic*. "Rotate enrolled keys" replaces the enrolled keys
with new ones the current key authorises.

## Notes

* Local mode lets the phone judge itself, so a fully compromised phone could
  lie to it. Production decisions are made by the server (Server tab).
* The test build is sideloaded, so "Not installed from Google Play" (+30) is
  expected; the verdict is still ALLOW on a clean phone.
* Play Integrity is not part of the scan: standard requests can only be
  decoded server-side with a linked Cloud project.

## Build

```bash
cd android
./gradlew :scanner:testReleaseUnitTest :scanner:assembleRelease
# → scanner/build/outputs/apk/release/scanner-release.apk
```

The release build is minified and **not debuggable** (a debuggable build would
flag itself); it is signed with the local debug key so it installs directly.
CI uploads the APK as the `device-trust-scanner-apk` artifact. Each machine's
debug key differs, so uninstall before installing a build from another machine.

## Run 13 (0.6.0)

The Native versus Kotlin group shows nine native checks with per-check availability and comparable snapshot results. A maps or TracerPid disagreement is a signal only when Kotlin snapshots are stable and the native check completed. Unavailable reads never count as a mismatch. The local verdict is diagnostic: Play Integrity, fleet history and independent official-signer verification require the server/integration. Offline revocation and unallowlisted SELF_SIGNED boot are blocking local findings. Existing Google-root/chain compatibility limitations remain listed in the run notes.

## Run 17 (0.8.0)

The server-verified scan and key rotation described above. The local Scan tab is unchanged and still labelled as a local diagnostic. History findings describe changes in hardware-attested evidence. They are not proof of compromise: an OS update legitimately changes the boot image. They also do not prove the evidence came from "the same phone".

## Run 31 (0.9.0-dev.2): report file

"Save report file" (choose Downloads or Drive) and "Share report file" (a `.json` attachment) are on the Scan tab (also after a failed scan) and the Server tab. The file lists everything that could **not** be scanned, each with its reason, a plain explanation and a developer hint, plus errors, phase timings, app and device context, the full scan report, and server and biometric results. See [RUN_31_SCANNER_DEBUG_REPORT.md](../../docs/RUN_31_SCANNER_DEBUG_REPORT.md).
