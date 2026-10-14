package com.devicetrust.client

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64

/** Signs the whole submission; does not prove physical co-location of a second key. */
object EnrollmentProof {
    fun data(challenge: Challenge, chain: List<ByteArray>, confirm: List<ByteArray>?,
             device: DeviceInfo, signals: JSONObject?): ByteArray {
        fun hashes(certs: List<ByteArray>) = JSONArray(certs.map {
            MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02x".format(b) }
        })
        val ids = JSONObject()
        mapOf("brand" to device.brand, "device" to device.device, "product" to device.product,
            "manufacturer" to device.manufacturer, "model" to device.model).forEach { (k, v) ->
            if (v.isNotEmpty()) ids.put(k, v)
        }
        return JSONObject().put("v", 1).put("purpose", "enrollment")
            .put("challengeId", challenge.challengeId)
            .put("nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.nonce))
            .put("chainSha256", hashes(chain))
            .put("confirmChainSha256", confirm?.let(::hashes) ?: JSONObject.NULL)
            .put("device", ids).put("signals", signals ?: JSONObject.NULL)
            .toString().toByteArray(Charsets.UTF_8)
    }
}
