package com.devicetrust.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

/** Transport to the device trust service (normally via the bank backend). */
interface TrustApi {
    suspend fun createChallenge(): Challenge
    suspend fun enroll(request: EnrollmentRequest): EnrollmentResult
}

/** Wire format shared with `device_trust/api.py`. */
object TrustJson {
    private val b64 = Base64.getEncoder()
    private val b64UrlDecoder = Base64.getUrlDecoder()

    fun parseChallenge(body: String): Challenge {
        val json = JSONObject(body)
        return Challenge(
            challengeId = json.getString("challengeId"),
            nonce = b64UrlDecoder.decode(json.getString("nonce")),
            expiresAtEpochSeconds = json.getLong("expiresAt"),
        )
    }

    fun encodeEnrollment(request: EnrollmentRequest): String = JSONObject().apply {
        put("challengeId", request.challengeId)
        put("attestationChain", JSONArray(request.attestationChain.map { b64.encodeToString(it) }))
        request.playIntegrityToken?.let { put("playIntegrityToken", it) }
        put(
            "device",
            JSONObject().apply {
                put("brand", request.device.brand)
                put("device", request.device.device)
                put("product", request.device.product)
                put("manufacturer", request.device.manufacturer)
                put("model", request.device.model)
            },
        )
    }.toString()

    fun parseEnrollment(body: String): EnrollmentResult {
        val json = JSONObject(body)
        val decision = when (val raw = json.getString("decision")) {
            "ALLOW" -> Decision.ALLOW
            "BLOCK" -> Decision.BLOCK
            else -> throw DeviceTrustException("unknown decision '$raw'")
        }
        return EnrollmentResult(
            decision = decision,
            decisionId = json.getString("decisionId"),
            deviceId = if (json.isNull("deviceId")) null else json.optString("deviceId").ifEmpty { null },
        )
    }
}

/**
 * Minimal HttpURLConnection client. [headers] lets the app attach its session
 * credentials so the trust endpoints are only reachable for logged-in users.
 */
class HttpTrustApi(
    baseUrl: String,
    private val headers: suspend () -> Map<String, String> = { emptyMap() },
    private val timeoutMillis: Int = 15_000,
    allowCleartextForTesting: Boolean = false,
) : TrustApi {
    private val base = baseUrl.trimEnd('/')

    init {
        require(base.startsWith("https://") || allowCleartextForTesting) { "trust API must use HTTPS" }
    }

    override suspend fun createChallenge(): Challenge =
        TrustJson.parseChallenge(post("/v1/challenges", "{}", expected = 201))

    override suspend fun enroll(request: EnrollmentRequest): EnrollmentResult =
        TrustJson.parseEnrollment(post("/v1/enrollments", TrustJson.encodeEnrollment(request), expected = 200))

    private suspend fun post(path: String, body: String, expected: Int): String {
        val extraHeaders = headers()
        return withContext(Dispatchers.IO) {
            val conn = URL(base + path).openConnection() as HttpURLConnection
            try {
                conn.requestMethod = "POST"
                conn.connectTimeout = timeoutMillis
                conn.readTimeout = timeoutMillis
                conn.doOutput = true
                conn.instanceFollowRedirects = false
                conn.setRequestProperty("Content-Type", "application/json")
                conn.setRequestProperty("Accept", "application/json")
                extraHeaders.forEach { (k, v) -> conn.setRequestProperty(k, v) }
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                val code = conn.responseCode
                if (code != expected) throw DeviceTrustException("trust API $path returned HTTP $code")
                conn.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
            } catch (e: IOException) {
                throw DeviceTrustException("trust API $path unreachable", e)
            } finally {
                conn.disconnect()
            }
        }
    }
}
