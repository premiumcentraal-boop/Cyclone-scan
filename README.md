# Cyclone Scan — Device Trust

Bank-grade Android device verification: is this a genuine, unmodified phone
running the real app?

**The phone collects evidence; the server decides.** Trust rests on
hardware-signed evidence (Android key attestation, checked against Google's
roots and revocation list) plus Google Play Integrity, never on checks that
run only inside the app.

| Folder | What |
|---|---|
| [`service/`](service/README.md) | Python verifier and HTTP API: key attestation, revocation list, Play Integrity, attested device identity. Makes the ALLOW / BLOCK decision. |
| [`android/`](android/README.md) | Kotlin client library that creates the attested key, fetches a bound Play Integrity token and enrolls. |

## Roadmap

1. **Phase 1 (done):** enrollment with hard-fail gates.
2. **Phase 2 (done):** device binding: sensitive actions signed with the enrolled hardware key; biometric-bound confirm key for high-risk actions; device revocation.
3. **Phase 3 (done):** client RASP signals (root, hooking, emulator, tampering, scam/remote-control indicators) and an explainable server-side risk score with an audit trail.
4. **Phase 4:** policy tuning, dashboards, red-team test matrix, fallbacks.

## Quick start

```bash
python -m pip install -e 'service[test]'
python -m pytest -q service/tests

cd android && ./gradlew :devicetrust:testDebugUnitTest :devicetrust:assembleRelease
```

Physical-device verification has not been done yet; see each folder's README.
