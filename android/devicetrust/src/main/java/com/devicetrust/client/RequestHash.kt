package com.devicetrust.client

import java.security.MessageDigest
import java.util.Base64

/**
 * Play Integrity `requestHash` values. Must match
 * `device_trust.play_integrity.enrollment_request_hash` on the server.
 */
object RequestHash {
    private val ENROLL_DOMAIN = "device-trust/enroll/v1".toByteArray(Charsets.US_ASCII)
    private val EVIDENCE_DOMAIN = "device-trust/enroll-evidence/v1".toByteArray(Charsets.US_ASCII)
    fun enrollmentEvidence(data: ByteArray): String = hash(EVIDENCE_DOMAIN, data)

    private val ACTION_DOMAIN = "device-trust/action/v1".toByteArray(Charsets.US_ASCII)
    private val SCAN_DOMAIN = "device-trust/scan-evidence/v1".toByteArray(Charsets.US_ASCII)
    private val ROTATION_DOMAIN = "device-trust/key-rotation/v1".toByteArray(Charsets.US_ASCII)

    /** Run 17: base64url(SHA-256("device-trust/scan-evidence/v1" || scan transcript)). Matches `scan_evidence.request_hash`. */
    fun scanEvidence(data: ByteArray): String = hash(SCAN_DOMAIN, data)

    /** Run 17: base64url(SHA-256("device-trust/key-rotation/v1" || rotation transcript)). */
    fun keyRotation(data: ByteArray): String = hash(ROTATION_DOMAIN, data)

    /** base64url(SHA-256("device-trust/enroll/v1" || nonce || attested key SPKI DER)), unpadded. */
    fun enrollment(nonce: ByteArray, publicKeySpki: ByteArray): String = hash(ENROLL_DOMAIN, nonce, publicKeySpki)

    /** base64url(SHA-256("device-trust/action/v1" || signedData)), unpadded. Matches `action_request_hash`. */
    fun action(signedData: ByteArray): String = hash(ACTION_DOMAIN, signedData)

    private fun hash(vararg parts: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").run {
            parts.forEach { update(it) }
            digest()
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
