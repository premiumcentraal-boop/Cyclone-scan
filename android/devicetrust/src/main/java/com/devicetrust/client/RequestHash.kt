package com.devicetrust.client

import java.security.MessageDigest
import java.util.Base64

/**
 * Play Integrity `requestHash` values. Must match
 * `device_trust.play_integrity.enrollment_request_hash` on the server.
 */
object RequestHash {
    private val ENROLL_DOMAIN = "device-trust/enroll/v1".toByteArray(Charsets.US_ASCII)

    /** base64url(SHA-256("device-trust/enroll/v1" || nonce || attested key SPKI DER)), unpadded. */
    fun enrollment(nonce: ByteArray, publicKeySpki: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").run {
            update(ENROLL_DOMAIN)
            update(nonce)
            update(publicKeySpki)
            digest()
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
