package com.devicetrust.client

import android.os.Build

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
)

enum class Decision { ALLOW, BLOCK }

/**
 * Server verdict. Failure reasons are intentionally not returned to the app in
 * production; support staff can look them up by [decisionId].
 */
data class EnrollmentResult(
    val decision: Decision,
    val decisionId: String,
    val deviceId: String?,
)

/** Locally remembered enrollment: the server device ID and the bound key alias. */
data class Enrollment(val deviceId: String, val keyAlias: String)

class DeviceTrustException(message: String, cause: Throwable? = null) : Exception(message, cause)
