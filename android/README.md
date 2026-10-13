# Device Trust — Android client

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
5. If the phone has a strong biometric enrolled, also creates a **confirm key**
   that can only sign after BiometricPrompt and is destroyed when biometrics change.
6. On ALLOW keeps the keys and deletes any previous ones; otherwise deletes the new keys.

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

### Signing sensitive actions (Phase 2)

```kotlin
// Low-risk action: device key, no prompt.
val login = trust.signAction("login")

// High-risk action: confirm key, unlocked by a strong biometric.
val payment = trust.signAction(
    type = "payment",
    params = JSONObject().put("payee", iban).put("amountCents", 12500).put("currency", "EUR"),
    authenticator = BiometricPromptAuthenticator(
        activity, title = "Confirm payment", subtitle = "€125.00 to $payeeName",
    ),
)
backend.submitPayment(payment)  // backend verifies with the trust service and executes the returned action
```

* `NotEnrolledException`: no enrollment, or the server revoked/forgot the device → `reset()` and `enroll()`.
* `ConfirmKeyInvalidatedException`: biometrics changed → re-enroll.
* `UserAuthenticationException`: the user cancelled the prompt.
* `hasConfirmKey()` tells you whether high-risk actions can be confirmed on this phone; if not, the server answers STEP_UP and your backend should use out-of-band verification.

Pass `cloudProjectNumber = null` for builds without Google Play services; the
server policy decides whether that is acceptable.

## Build & test

```bash
cd android
./gradlew :devicetrust:testDebugUnitTest :devicetrust:assembleRelease :devicetrust:lintRelease
```

Set `sdk.dir` in `local.properties` (or `ANDROID_HOME`) first.

## Status

JVM unit tests cover the wire format, request-hash vectors shared with the
server, key lifecycle on ALLOW / BLOCK / transport failure, and signed-action
construction and signatures (with software keys standing in for AndroidKeyStore). Key generation
and Play Integrity need a real device: **physical-device verification has not
been done yet.**
