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

    /** Single-use challenge bound to an enrolled device, for signing one action. */
    suspend fun createActionChallenge(deviceId: String): Challenge

    /**
     * Verify a signed action. Normally your backend calls this, not the app:
     * the backend must execute only the action the trust service returns.
     */
    suspend fun verifyAction(action: SignedAction): ActionResult

    /**
     * Run 17: single-use challenge for a server-verified scan or a key rotation
     * ([ScanEvidence.PURPOSE_SCAN] / [ScanEvidence.PURPOSE_KEY_ROTATION]).
     * @throws NotEnrolledException when the server does not know the device as active.
     */
    suspend fun createDeviceChallenge(deviceId: String, purpose: String): Challenge =
        throw UnsupportedOperationException("this transport does not support Run 17 device challenges")

    /** Run 17: the server's verdict on one signed scan. */
    suspend fun verifyScan(request: ScanRequest): ServerScan.Verified =
        throw UnsupportedOperationException("this transport does not support server-verified scans")

    /** Run 17: ask the server to replace the enrolled key with one the old key authorised. */
    suspend fun rotateKey(request: KeyRotationRequest): KeyRotationResult =
        throw UnsupportedOperationException("this transport does not support key rotation")
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
        request.confirmKeyChain?.let { chain ->
            put("confirmKeyChain", JSONArray(chain.map { b64.encodeToString(it) }))
        }
        request.signals?.let { put("signals", it) }
        request.evidenceData?.let { put("evidenceData", b64.encodeToString(it)) }
        request.evidenceSignature?.let { put("evidenceSignature", b64.encodeToString(it)) }
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

    fun encodeActionChallengeRequest(deviceId: String): String =
        JSONObject().put("deviceId", deviceId).toString()

    /**
     * The document the device signs. The server parses these exact bytes, so
     * field order and whitespace do not matter, but every field must be present.
     */
    fun signedActionData(
        deviceId: String,
        challenge: Challenge,
        type: String,
        params: JSONObject,
        timestampMillis: Long,
        signals: JSONObject? = null,
    ): ByteArray = JSONObject().apply {
        put("v", 1)
        put("deviceId", deviceId)
        put("challengeId", challenge.challengeId)
        put("nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(challenge.nonce))
        put("ts", timestampMillis)
        put("action", JSONObject().put("type", type).put("params", params))
        // Signed together with the action, so nothing between app and server can strip it.
        signals?.let { put("signals", it) }
    }.toString().toByteArray(Charsets.UTF_8)

    fun encodeAction(action: SignedAction): String = JSONObject().apply {
        put("deviceId", action.deviceId)
        put("challengeId", action.challengeId)
        put("signedData", b64.encodeToString(action.signedData))
        put("signature", b64.encodeToString(action.signature))
        put("key", action.key.wire)
        action.playIntegrityToken?.let { put("playIntegrityToken", it) }
    }.toString()

    fun parseActionResult(body: String): ActionResult {
        val json = JSONObject(body)
        val decision = when (val raw = json.getString("decision")) {
            "ALLOW" -> ActionDecision.ALLOW
            "STEP_UP" -> ActionDecision.STEP_UP
            "BLOCK" -> ActionDecision.BLOCK
            else -> throw DeviceTrustException("unknown decision '$raw'")
        }
        val action = json.optJSONObject("action")
        return ActionResult(
            decision = decision,
            decisionId = json.getString("decisionId"),
            actionType = action?.getString("type"),
            paramsJson = action?.getJSONObject("params")?.toString(),
            diagnostics = parseDiagnostics(json),
        )
    }

    private fun parseDiagnostics(json: JSONObject): ServerDiagnostics? {
        if (!json.has("reasons") && !json.has("risk")) return null
        fun strings(key: String) = json.optJSONArray(key)?.let { a -> (0 until a.length()).map { a.getString(it) } }.orEmpty()
        val risk = json.optJSONObject("risk")
        val factors = risk?.optJSONArray("factors")?.let { a ->
            (0 until a.length()).map { a.getJSONObject(it).let { f -> f.getString("factor") to f.getInt("points") } }
        }.orEmpty()
        return ServerDiagnostics(strings("reasons"), strings("warnings"), risk?.getInt("score"), factors)
    }

    fun encodeDeviceChallengeRequest(deviceId: String, purpose: String): String =
        JSONObject().put("deviceId", deviceId).put("purpose", purpose).toString()

    fun encodeScan(request: ScanRequest): String = JSONObject().apply {
        put("deviceId", request.deviceId)
        put("challengeId", request.challengeId)
        put("scanData", b64.encodeToString(request.scanData))
        put("signature", b64.encodeToString(request.signature))
        request.freshAttestationChain?.let { chain ->
            put("freshAttestationChain", JSONArray(chain.map { b64.encodeToString(it) }))
        }
        request.playIntegrityToken?.let { put("playIntegrityToken", it) }
    }.toString()

    fun encodeKeyRotation(request: KeyRotationRequest): String = JSONObject().apply {
        put("deviceId", request.deviceId)
        put("challengeId", request.challengeId)
        put("rotationData", b64.encodeToString(request.rotationData))
        put("oldKeySignature", b64.encodeToString(request.oldKeySignature))
        put("newKeySignature", b64.encodeToString(request.newKeySignature))
        put("newAttestationChain", JSONArray(request.newAttestationChain.map { b64.encodeToString(it) }))
        request.newConfirmKeyChain?.let { chain ->
            put("newConfirmKeyChain", JSONArray(chain.map { b64.encodeToString(it) }))
        }
        request.playIntegrityToken?.let { put("playIntegrityToken", it) }
    }.toString()

    private fun decision(raw: String) = when (raw) {
        "ALLOW" -> Decision.ALLOW
        "STEP_UP" -> Decision.STEP_UP
        "BLOCK" -> Decision.BLOCK
        else -> throw MalformedResponseException("unknown decision '$raw'")
    }

    /** Strict: a response without every documented field is malformed, never "verified". */
    fun parseScan(body: String): ServerScan.Verified = try {
        val json = JSONObject(body)
        val evidence = json.getJSONObject("evidence")
        fun status(key: String) = try {
            EvidenceStatus.valueOf(evidence.getString(key))
        } catch (e: IllegalArgumentException) {
            throw MalformedResponseException("unknown $key status", e)
        }
        val policy = json.getJSONObject("policy")
        val history = json.optJSONObject("history")?.let { h ->
            val changes = h.getJSONArray("changes")
            ScanHistory(
                snapshots = h.getInt("snapshots"),
                previousAtEpochSeconds = if (h.isNull("previousAt")) null else h.optDouble("previousAt"),
                previousSource = if (h.isNull("previousSource")) null else h.optString("previousSource"),
                compared = h.getBoolean("compared"),
                changes = (0 until changes.length()).map { i ->
                    changes.getJSONObject(i).let { HistoryChange(it.getString("code"), it.getString("level"), it.getString("field")) }
                },
            )
        }
        val coverage = json.optJSONObject("coverage")?.let { c -> c.keys().asSequence().associateWith { c.getInt(it) } }
        val verifiedAt = json.getLong("verifiedAt")
        val freshUntil = json.getLong("freshUntil")
        if (freshUntil < verifiedAt) throw MalformedResponseException("freshUntil precedes verifiedAt")
        ServerScan.Verified(
            decision = decision(json.getString("decision")),
            decisionId = json.getString("decisionId"),
            verifiedAtMillis = verifiedAt,
            freshUntilMillis = freshUntil,
            policy = ScanPolicy(policy.getString("version"), policy.getString("digest"), policy.getString("verifierRuleset")),
            evidence = ScanEvidenceStatus(
                status("deviceKeySignature"), status("freshAttestation"), status("playIntegrity"), status("clientSignals"),
            ),
            coverage = coverage,
            history = history,
            diagnostics = parseDiagnostics(json),
        )
    } catch (e: org.json.JSONException) {
        throw MalformedResponseException("scan response is not the documented shape", e)
    }

    fun parseKeyRotation(body: String): KeyRotationResult = try {
        val json = JSONObject(body)
        KeyRotationResult(
            decision = decision(json.getString("decision")),
            decisionId = json.getString("decisionId"),
            rotated = json.getBoolean("rotated"),
            hasConfirmKey = if (json.has("hasConfirmKey")) json.getBoolean("hasConfirmKey") else null,
            diagnostics = parseDiagnostics(json),
        )
    } catch (e: org.json.JSONException) {
        throw MalformedResponseException("key rotation response is not the documented shape", e)
    }

    fun parseEnrollment(body: String): EnrollmentResult {
        val json = JSONObject(body)
        val decision = when (val raw = json.getString("decision")) {
            "ALLOW" -> Decision.ALLOW
            "STEP_UP" -> Decision.STEP_UP
            "BLOCK" -> Decision.BLOCK
            else -> throw DeviceTrustException("unknown decision '$raw'")
        }
        return EnrollmentResult(
            decision = decision,
            decisionId = json.getString("decisionId"),
            deviceId = if (json.isNull("deviceId")) null else json.optString("deviceId").ifEmpty { null },
            diagnostics = parseDiagnostics(json),
            deviceStatus = json.optString("deviceStatus", "").takeIf { it == "active" || it == "pending" },
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

    override suspend fun createActionChallenge(deviceId: String): Challenge = try {
        TrustJson.parseChallenge(
            post("/v1/action-challenges", TrustJson.encodeActionChallengeRequest(deviceId), expected = 201),
        )
    } catch (e: HttpStatusException) {
        if (e.code == 404) throw NotEnrolledException() else throw e
    }

    override suspend fun verifyAction(action: SignedAction): ActionResult =
        TrustJson.parseActionResult(post("/v1/actions/verify", TrustJson.encodeAction(action), expected = 200))

    override suspend fun createDeviceChallenge(deviceId: String, purpose: String): Challenge = try {
        TrustJson.parseChallenge(
            post("/v1/device-challenges", TrustJson.encodeDeviceChallengeRequest(deviceId, purpose), expected = 201),
        )
    } catch (e: HttpStatusException) {
        if (e.code == 404) throw NotEnrolledException() else throw e
    }

    override suspend fun verifyScan(request: ScanRequest): ServerScan.Verified =
        TrustJson.parseScan(post("/v1/scans/verify", TrustJson.encodeScan(request), expected = 200))

    override suspend fun rotateKey(request: KeyRotationRequest): KeyRotationResult =
        TrustJson.parseKeyRotation(post("/v1/key-rotations", TrustJson.encodeKeyRotation(request), expected = 200))

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
                if (code != expected) throw HttpStatusException(path, code)
                conn.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
            } catch (e: IOException) {
                throw DeviceTrustException("trust API $path unreachable", e)
            } finally {
                conn.disconnect()
            }
        }
    }
}

class HttpStatusException(path: String, val code: Int) : DeviceTrustException("trust API $path returned HTTP $code")
