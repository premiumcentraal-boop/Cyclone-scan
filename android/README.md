# Device Trust — Android client (Phase 1)

Kotlin library (`:devicetrust`, minSdk 26) that enrolls a device with the
[Device Trust Service](../service/README.md). It gathers evidence;
the server makes every trust decision.

What it does on `enroll()`:

1. Gets a single-use challenge from the server.
2. Generates a non-exportable EC P-256 key in AndroidKeyStore with that
   challenge in its attestation certificate. StrongBox is preferred, then the
   TEE. Android 12+ also includes device-property attestation (brand/model/…).
3. Requests a Play Integrity **standard** token whose `requestHash` binds the
   challenge and the attested public key (`RequestHash.enrollment`).
4. Sends chain + token + `Build` values to the server.
5. On ALLOW keeps the key as the device-binding key (Phase 2 signs sensitive
   actions with it) and deletes any previous one; otherwise deletes the new key.

No serial, IMEI, account or secret data is collected.

## Use

```kotlin
val api = HttpTrustApi(
    baseUrl = "https://api.yourbank.example/device-trust",
    headers = { mapOf("Authorization" to "Bearer ${session.accessToken()}") },
)
val trust = DeviceTrustClient(context, api, cloudProjectNumber = 123456789012L) // null = no Play Integrity

lifecycleScope.launch {
    when (trust.enroll().decision) {
        Decision.ALLOW -> proceed()
        Decision.BLOCK -> showDeviceNotSupported()
    }
}
```

Pass `cloudProjectNumber = null` for builds without Google Play services; the
server policy decides whether that is acceptable.

## Build & test

```bash
cd android
./gradlew :devicetrust:testDebugUnitTest :devicetrust:assembleRelease :devicetrust:lintRelease
```

Set `sdk.dir` in `local.properties` (or `ANDROID_HOME`) first.

## Status

JVM unit tests cover the wire format, the request-hash vector shared with the
server, and key lifecycle on ALLOW / BLOCK / transport failure. Key generation
and Play Integrity need a real device: **physical-device verification has not
been done yet.**
