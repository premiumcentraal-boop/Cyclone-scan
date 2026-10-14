package com.devicetrust.client

import android.os.Build
import org.json.JSONObject

/** A single-use server challenge. [nonce] goes into the key attestation certificate. */
class Challenge(
    val challengeId: String,
    val nonce: ByteArray,
    val expiresAtEpochSeconds: Long,
)

/**
 * Build values the app reports. The server compares them with the values the
 * secure hardware attested, so spoofing these (Xposed, Magisk props) is detected.
 * No serial, IMEI or other unique identifiers are ever collected.
 */
data class DeviceInfo(
    val brand: String,
    val device: String,
    val product: String,
    val manufacturer: String,
    val model: String,
) {
    companion object {
        fun current(): DeviceInfo = DeviceInfo(
            brand = Build.BRAND.orEmpty(),
            device = Build.DEVICE.orEmpty(),
            product = Build.PRODUCT.orEmpty(),
            manufacturer = Build.MANUFACTURER.orEmpty(),
            model = Build.MODEL.orEmpty(),
        )
    }
}

class EnrollmentRequest(
    val challengeId: String,
    /** DER certificates, leaf first, exactly as Android KeyStore returns them. */
    val attestationChain: List<ByteArray>,
    val playIntegrityToken: String?,
    val device: DeviceInfo,
    /** Optional biometric-bound key chain (same challenge), leaf first. */
    val confirmKeyChain: List<ByteArray>? = null,
    /** Optional client signal report (Phase 3). */
    val signals: JSONObject? = null,
    val evidenceData: ByteArray? = null,
    val evidenceSignature: ByteArray? = null,
)

/**
 * ALLOW: enrolled. STEP_UP: enrolled, but the server saw risk; the bank should
 * verify the customer (e.g. video ID) before trusting this device. BLOCK: not enrolled.
 */
enum class Decision { ALLOW, STEP_UP, BLOCK }

/**
 * Server verdict. Failure reasons are intentionally not returned to the app in
 * production; support staff can look them up by [decisionId].
 */
data class EnrollmentResult(
    val decision: Decision,
    val decisionId: String,
    val deviceId: String?,
    /** Only when the server runs with --expose-reasons (development). */
    val diagnostics: ServerDiagnostics? = null,
    /**
     * Run 16 lifecycle state of the enrolled device: "active", or "pending" until the
     * app's backend completes an authenticated step-up. Null from older servers.
     */
    val deviceStatus: String? = null,
)

/** Reason codes and risk breakdown, returned only by development servers. */
data class ServerDiagnostics(
    val reasons: List<String>,
    val warnings: List<String>,
    val riskScore: Int?,
    val riskFactors: List<Pair<String, Int>>,
)

/**
 * Locally remembered enrollment: the server device ID, the device-binding key
 * alias and, when the device has strong biometrics, the confirm key alias.
 */
data class Enrollment(val deviceId: String, val keyAlias: String, val confirmKeyAlias: String? = null)

/** Which enrolled key signed an action. */
enum class SigningKey(val wire: String) {
    /** Device-binding key: proves the request comes from the enrolled phone. */
    DEVICE("device"),

    /** Biometric-bound key: enforces biometric authentication before signing; it does not attest the displayed UI. */
    CONFIRM("confirm"),
}

/**
 * A sensitive action signed by the enrolled hardware key. Send it to your
 * backend together with the request; the backend asks the trust service to
 * verify it and executes only the action the service returns.
 */
class SignedAction(
    val deviceId: String,
    val challengeId: String,
    /** The exact bytes that were signed (UTF-8 JSON). */
    val signedData: ByteArray,
    /** DER-encoded ECDSA P-256 / SHA-256 signature. */
    val signature: ByteArray,
    val key: SigningKey,
    val playIntegrityToken: String?,
)

enum class ActionDecision { ALLOW, STEP_UP, BLOCK }

data class ActionResult(
    val decision: ActionDecision,
    val decisionId: String,
    /** Only on ALLOW: the action type the device signed. */
    val actionType: String?,
    /** Only on ALLOW: the params the device signed, as JSON text. */
    val paramsJson: String?,
    /** Only when the server runs with --expose-reasons (development). */
    val diagnostics: ServerDiagnostics? = null,
)

open class DeviceTrustException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The device has no enrollment (or it was removed); call enroll() first. */
class NotEnrolledException : DeviceTrustException("device is not enrolled")

/**
 * The confirm key was permanently invalidated, usually because a new
 * fingerprint/face was enrolled. Re-enroll to create a new confirm key.
 */
class ConfirmKeyInvalidatedException(cause: Throwable? = null) :
    DeviceTrustException("confirm key invalidated; re-enrollment required", cause)
