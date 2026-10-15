package com.devicetrust.client

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64

/**
 * Run 17 transcripts signed by the enrolled device key: a server-verified scan and a key
 * rotation. Must match `device_trust/scan_evidence.py`. The server verifies these exact
 * bytes; field order does not matter, but the field set is exact.
 *
 * Signing proves the holder of the enrolled key authorised this evidence. It does not
 * prove that a fresh or new key lives on the same physical phone.
 */
object ScanEvidence {
    const val PURPOSE_SCAN = "scan"
    const val PURPOSE_KEY_ROTATION = "key-rotation"

    fun scan(
        deviceId: String,
        challenge: Challenge,
        timestampMillis: Long,
        freshChain: List<ByteArray>?,
        device: DeviceInfo,
        signals: JSONObject?,
    ): ByteArray = common(PURPOSE_SCAN, deviceId, challenge, timestampMillis, device)
        .put("freshChainSha256", freshChain?.let(::digests) ?: JSONObject.NULL)
        // Snapshotted by the caller before signing; never appended to afterwards.
        .put("signals", signals ?: JSONObject.NULL)
        .toString().toByteArray(Charsets.UTF_8)

    fun keyRotation(
        deviceId: String,
        challenge: Challenge,
        timestampMillis: Long,
        newChain: List<ByteArray>,
        newConfirmChain: List<ByteArray>?,
        device: DeviceInfo,
    ): ByteArray = common(PURPOSE_KEY_ROTATION, deviceId, challenge, timestampMillis, device)
        .put("newChainSha256", digests(newChain))
        .put("newConfirmChainSha256", newConfirmChain?.let(::digests) ?: JSONObject.NULL)
        .toString().toByteArray(Charsets.UTF_8)

    private fun common(purpose: String, deviceId: String, challenge: Challenge, ts: Long, device: DeviceInfo) =
        JSONObject().put("v", 1).put("purpose", purpose).put("deviceId", deviceId)
            .put("challengeId", challenge.challengeId)
            .put("nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.nonce))
            .put("ts", ts)
            .put("device", ids(device))

    private fun ids(device: DeviceInfo) = JSONObject().apply {
        mapOf("brand" to device.brand, "device" to device.device, "product" to device.product,
            "manufacturer" to device.manufacturer, "model" to device.model).forEach { (k, v) ->
            if (v.isNotEmpty()) put(k, v)
        }
    }

    private fun digests(certs: List<ByteArray>) = JSONArray(certs.map {
        MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02x".format(b) }
    })
}

class ScanRequest(
    val deviceId: String,
    val challengeId: String,
    /** The exact signed transcript bytes. */
    val scanData: ByteArray,
    /** DER ECDSA signature by the enrolled device key. */
    val signature: ByteArray,
    /** Chain of the ephemeral key generated with the scan nonce, leaf first; null if none. */
    val freshAttestationChain: List<ByteArray>?,
    val playIntegrityToken: String?,
)

class KeyRotationRequest(
    val deviceId: String,
    val challengeId: String,
    val rotationData: ByteArray,
    /** By the currently enrolled device key: authorises the new key. */
    val oldKeySignature: ByteArray,
    /** By the new key: proves possession. */
    val newKeySignature: ByteArray,
    val newAttestationChain: List<ByteArray>,
    val newConfirmKeyChain: List<ByteArray>?,
)

/** Per-evidence verification status, exactly as the server reports it. */
enum class EvidenceStatus { VERIFIED, FAILED, UNAVAILABLE, NOT_PROVIDED, SIGNED, MALFORMED }

data class ScanEvidenceStatus(
    val deviceKeySignature: EvidenceStatus,
    val freshAttestation: EvidenceStatus,
    val playIntegrity: EvidenceStatus,
    val clientSignals: EvidenceStatus,
)

/** Which policy produced a verdict: the operator's label and a digest the label cannot fake. */
data class ScanPolicy(val version: String, val digest: String, val verifierRuleset: String)

/** One history finding (Run 22 vocabulary plus FRESH_KEY_AUTHORIZED / KEY_ROTATED). Diagnostic only. */
data class HistoryChange(val code: String, val level: String, val field: String)

data class ScanHistory(
    val snapshots: Int,
    val previousAtEpochSeconds: Double?,
    val previousSource: String?,
    /** False when no fresh attested evidence was recorded, so nothing could be compared. */
    val compared: Boolean,
    val changes: List<HistoryChange>,
)

/** How a scan outcome may be presented. Only the VERIFIED_* labels may say "server-verified". */
enum class ScanLabel {
    /** Signature, fresh attestation and Play Integrity verified; within freshUntil. */
    VERIFIED_FRESH,
    /** The server verified the signature, but fresh attestation or Play evidence is missing, failed or unavailable. */
    VERIFIED_PARTIAL,
    /** A server verdict older than its freshUntil: re-scan before relying on it. */
    VERIFIED_EXPIRED,
    /** The server answered BLOCK, or could not authenticate the scan. */
    REJECTED,
    /** No server verdict at all (not enrolled, unreachable, refused, malformed response). */
    UNAVAILABLE,
}

enum class UnavailableReason {
    NOT_ENROLLED,
    /** Unknown, not owned, pending, revoked or quarantined (the server gives the same answer). */
    DEVICE_NOT_ACTIVE,
    /** The enrolled key is gone from the keystore (reset, restore to another phone). Re-enroll. */
    KEY_UNAVAILABLE,
    NETWORK,
    SERVER_ERROR,
    MALFORMED_RESPONSE,
    UNSUPPORTED_TRANSPORT,
}

/** Outcome of [DeviceTrustClient.verifiedScan]. Never constructed from a local result. */
sealed interface ServerScan {
    fun label(nowMillis: Long): ScanLabel

    data class Verified(
        val decision: Decision,
        val decisionId: String,
        val verifiedAtMillis: Long,
        val freshUntilMillis: Long,
        val policy: ScanPolicy,
        val evidence: ScanEvidenceStatus,
        /** Run 14 client check coverage counts, if signals were reported. */
        val coverage: Map<String, Int>?,
        val history: ScanHistory?,
        /** Only when the server runs with --expose-reasons (development). */
        val diagnostics: ServerDiagnostics? = null,
        /** Client side: a Play Integrity token source was configured for this scan. */
        val playRequested: Boolean = false,
    ) : ServerScan {
        override fun label(nowMillis: Long): ScanLabel = when {
            decision == Decision.BLOCK || evidence.deviceKeySignature != EvidenceStatus.VERIFIED -> ScanLabel.REJECTED
            nowMillis > freshUntilMillis -> ScanLabel.VERIFIED_EXPIRED
            partialBecause().isNotEmpty() -> ScanLabel.VERIFIED_PARTIAL
            else -> ScanLabel.VERIFIED_FRESH
        }

        /** Human-readable gaps that make this result partial (empty when complete). */
        fun partialBecause(): List<String> = buildList {
            if (evidence.freshAttestation != EvidenceStatus.VERIFIED) {
                add("fresh attestation ${evidence.freshAttestation.name.lowercase().replace('_', ' ')}")
            }
            if (evidence.playIntegrity != EvidenceStatus.VERIFIED) {
                add(if (!playRequested && evidence.playIntegrity == EvidenceStatus.NOT_PROVIDED) {
                    "Play Integrity not requested (no Cloud project configured)"
                } else {
                    "Play Integrity ${evidence.playIntegrity.name.lowercase().replace('_', ' ')}"
                })
            }
        }
    }

    data class Unavailable(val reason: UnavailableReason, val detail: String? = null) : ServerScan {
        override fun label(nowMillis: Long) = ScanLabel.UNAVAILABLE
    }
}

data class KeyRotationResult(
    val decision: Decision,
    val decisionId: String,
    /** True only when the server replaced the key; the client then switched to the new aliases. */
    val rotated: Boolean,
    val hasConfirmKey: Boolean?,
    val diagnostics: ServerDiagnostics? = null,
)

/** The server's answer did not have the documented shape. */
class MalformedResponseException(message: String, cause: Throwable? = null) : DeviceTrustException(message, cause)
