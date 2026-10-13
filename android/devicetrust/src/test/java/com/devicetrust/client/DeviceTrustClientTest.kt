package com.devicetrust.client

import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64

class RequestHashTest {
    @Test
    fun matchesServerVector() {
        // device_trust.play_integrity.enrollment_request_hash(bytes(range(32)), b"spki-test")
        val nonce = ByteArray(32) { it.toByte() }
        assertEquals(
            "kSxGv5NLmYFjfzmtSyqp4Uk0GCw70RqgqVHyFHa8xUY",
            RequestHash.enrollment(nonce, "spki-test".toByteArray()),
        )
    }

    @Test
    fun actionHashMatchesServerVector() {
        // device_trust.actions.action_request_hash(b'{"v":1}')
        assertEquals("55Sw2PkEIGH8rqsY5hq-r-9PRHu3KQEjUbKimDxWKUM", RequestHash.action("{\"v\":1}".toByteArray()))
    }
}

class TrustJsonTest {
    @Test
    fun parsesChallenge() {
        val c = TrustJson.parseChallenge("""{"challengeId":"c1","nonce":"AAECAw","expiresAt":1760000000}""")
        assertEquals("c1", c.challengeId)
        assertTrue(byteArrayOf(0, 1, 2, 3).contentEquals(c.nonce))
        assertEquals(1760000000L, c.expiresAtEpochSeconds)
    }

    @Test
    fun encodesEnrollmentWithoutTokenWhenAbsent() {
        val json = JSONObject(
            TrustJson.encodeEnrollment(
                EnrollmentRequest("c1", listOf(byteArrayOf(1, 2), byteArrayOf(3)), null, DEVICE),
            ),
        )
        assertEquals("c1", json.getString("challengeId"))
        assertEquals("AQI=", json.getJSONArray("attestationChain").getString(0))
        assertFalse(json.has("playIntegrityToken"))
        assertEquals("Pixel 8", json.getJSONObject("device").getString("model"))
    }

    @Test
    fun parsesDecisions() {
        val allow = TrustJson.parseEnrollment("""{"decision":"ALLOW","decisionId":"dec_1","deviceId":"dev_1"}""")
        assertEquals(EnrollmentResult(Decision.ALLOW, "dec_1", "dev_1"), allow)
        val block = TrustJson.parseEnrollment("""{"decision":"BLOCK","decisionId":"dec_2"}""")
        assertEquals(EnrollmentResult(Decision.BLOCK, "dec_2", null), block)
    }

    @Test(expected = DeviceTrustException::class)
    fun rejectsUnknownDecision() {
        TrustJson.parseEnrollment("""{"decision":"MAYBE","decisionId":"d"}""")
    }

    @Test
    fun encodesSignedActionForServer() {
        val json = JSONObject(
            TrustJson.encodeAction(
                SignedAction("dev_1", "act_1", byteArrayOf(1, 2), byteArrayOf(3), SigningKey.CONFIRM, null),
            ),
        )
        assertEquals("confirm", json.getString("key"))
        assertEquals("AQI=", json.getString("signedData"))
        assertEquals("Aw==", json.getString("signature"))
        assertFalse(json.has("playIntegrityToken"))
    }

    @Test
    fun parsesActionResults() {
        val allow = TrustJson.parseActionResult(
            """{"decision":"ALLOW","decisionId":"d1","action":{"type":"payment","params":{"amountCents":5}}}""",
        )
        assertEquals(ActionDecision.ALLOW, allow.decision)
        assertEquals("payment", allow.actionType)
        assertEquals(5, JSONObject(allow.paramsJson!!).getInt("amountCents"))
        assertEquals(
            Decision.STEP_UP,
            TrustJson.parseEnrollment("""{"decision":"STEP_UP","decisionId":"d","deviceId":"x"}""").decision,
        )
        val stepUp = TrustJson.parseActionResult("""{"decision":"STEP_UP","decisionId":"d2"}""")
        assertEquals(ActionResult(ActionDecision.STEP_UP, "d2", null, null), stepUp)
    }

    @Test
    fun encodesConfirmKeyChainInEnrollment() {
        val json = JSONObject(
            TrustJson.encodeEnrollment(
                EnrollmentRequest("c", listOf(byteArrayOf(1)), null, DEVICE, listOf(byteArrayOf(2), byteArrayOf(3))),
            ),
        )
        assertEquals(2, json.getJSONArray("confirmKeyChain").length())
    }

    @Test(expected = IllegalArgumentException::class)
    fun refusesCleartext() {
        HttpTrustApi("http://bank.example")
    }
}

class DeviceTrustClientTest {
    private val nonce = ByteArray(32) { 7 }
    private val spki = "attested-spki".toByteArray()

    private class FakeAttester(private val spki: ByteArray, private val confirmSupported: Boolean = true) : KeyAttester {
        val live = mutableSetOf<String>()
        val keys = mutableMapOf<String, java.security.KeyPair>()
        var lastChallenge: ByteArray? = null
        override fun generate(alias: String, challenge: ByteArray): AttestedKey {
            lastChallenge = challenge
            live += alias
            keys[alias] = ec()
            return AttestedKey(alias, listOf(byteArrayOf(1), byteArrayOf(2)), spki, strongBox = false)
        }
        override fun generateConfirmKey(alias: String, challenge: ByteArray): AttestedKey? {
            if (!confirmSupported) return null
            live += alias
            keys[alias] = ec()
            return AttestedKey(alias, listOf(byteArrayOf(3), byteArrayOf(4)), "confirm".toByteArray(), strongBox = false)
        }
        override fun signer(alias: String): java.security.Signature {
            val pair = keys[alias]?.takeIf { alias in live } ?: throw NotEnrolledException()
            return java.security.Signature.getInstance("SHA256withECDSA").apply { initSign(pair.private) }
        }
        override fun delete(alias: String) {
            live -= alias
        }
        private fun ec() = java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
    }

    private class MemoryStore(var value: Enrollment? = null) : EnrollmentStore {
        override fun load() = value
        override fun save(enrollment: Enrollment) { value = enrollment }
        override fun clear() { value = null }
    }

    private inner class FakeApi(private val result: EnrollmentResult?, private val error: Exception? = null) : TrustApi {
        var sent: EnrollmentRequest? = null
        var actionChallenges = 0
        override suspend fun createChallenge() = Challenge("ch_1", nonce, 0)
        override suspend fun enroll(request: EnrollmentRequest): EnrollmentResult {
            sent = request
            error?.let { throw it }
            return result!!
        }
        override suspend fun createActionChallenge(deviceId: String): Challenge {
            actionChallenges++
            return Challenge("act_$actionChallenges", ByteArray(32) { 9 }, 0)
        }
        override suspend fun verifyAction(action: SignedAction): ActionResult = error("not used")
    }

    private var aliasCounter = 0
    // integrity stays last so existing tests can pass it as a trailing lambda.
    private fun client(
        api: TrustApi,
        attester: KeyAttester,
        store: EnrollmentStore,
        signals: com.devicetrust.client.signals.SignalCollector? = null,
        integrity: IntegrityTokenSource? = null,
    ) = DeviceTrustClient(
        api, attester, integrity, store, { DEVICE }, { "alias_${++aliasCounter}" }, { 1_760_000_000_000L }, signals,
    )

    @Test
    fun allowKeepsNewKeyAndReplacesOldBinding() = runTest {
        val attester = FakeAttester(spki).apply { live += "old_alias" }
        val store = MemoryStore(Enrollment("dev_old", "old_alias"))
        var hashSeen: String? = null
        val api = FakeApi(EnrollmentResult(Decision.ALLOW, "dec_1", "dev_new"))

        val result = client(api, attester, store) { hash -> hashSeen = hash; "play-token" }.enroll()

        assertEquals(Decision.ALLOW, result.decision)
        assertEquals(Enrollment("dev_new", "alias_1", "alias_2"), store.value)
        assertEquals(setOf("alias_1", "alias_2"), attester.live)
        assertTrue(nonce.contentEquals(attester.lastChallenge))
        assertEquals(RequestHash.enrollment(nonce, spki), hashSeen)
        assertEquals("play-token", api.sent!!.playIntegrityToken)
        assertEquals("ch_1", api.sent!!.challengeId)
        assertEquals(DEVICE, api.sent!!.device)
    }

    @Test
    fun blockDeletesNewKeyAndKeepsPreviousEnrollment() = runTest {
        val attester = FakeAttester(spki).apply { live += "old_alias" }
        val store = MemoryStore(Enrollment("dev_old", "old_alias"))
        val result = client(FakeApi(EnrollmentResult(Decision.BLOCK, "dec_2", null)), attester, store, null).enroll()

        assertEquals(Decision.BLOCK, result.decision)
        assertEquals(Enrollment("dev_old", "old_alias"), store.value)
        assertEquals(setOf("old_alias"), attester.live)
    }

    @Test
    fun enrollmentSendsConfirmKeyChainWhenSupported() = runTest {
        val api = FakeApi(EnrollmentResult(Decision.ALLOW, "d", "dev_1"))
        client(api, FakeAttester(spki), MemoryStore(), null).enroll()
        assertEquals(2, api.sent!!.confirmKeyChain!!.size)
        assertTrue(byteArrayOf(3).contentEquals(api.sent!!.confirmKeyChain!![0]))
    }

    @Test
    fun enrollmentWithoutBiometricsHasNoConfirmKey() = runTest {
        val api = FakeApi(EnrollmentResult(Decision.ALLOW, "d", "dev_1"))
        val store = MemoryStore()
        val attester = FakeAttester(spki, confirmSupported = false)
        client(api, attester, store, null).enroll()
        assertNull(api.sent!!.confirmKeyChain)
        assertEquals(Enrollment("dev_1", "alias_1", null), store.value)
        assertEquals(setOf("alias_1"), attester.live)
    }

    @Test
    fun replacingEnrollmentDeletesOldConfirmKey() = runTest {
        val attester = FakeAttester(spki).apply { live += setOf("old", "old_confirm") }
        val store = MemoryStore(Enrollment("dev_old", "old", "old_confirm"))
        client(FakeApi(EnrollmentResult(Decision.ALLOW, "d", "dev_new")), attester, store, null).enroll()
        assertEquals(setOf("alias_1", "alias_2"), attester.live)
    }

    @Test
    fun signsActionWithDeviceKey() = runTest {
        val attester = FakeAttester(spki)
        val store = MemoryStore()
        val api = FakeApi(EnrollmentResult(Decision.ALLOW, "d", "dev_1"))
        var hashSeen: String? = null
        val c = client(api, attester, store) { h -> hashSeen = h; "tok" }
        c.enroll()

        val signed = c.signAction("payment", JSONObject().put("amountCents", 1250).put("payee", "NL91ABNA0417164300"))

        assertEquals(SigningKey.DEVICE, signed.key)
        assertEquals("dev_1", signed.deviceId)
        assertEquals("act_1", signed.challengeId)
        val doc = JSONObject(String(signed.signedData, Charsets.UTF_8))
        assertEquals(1, doc.getInt("v"))
        assertEquals("dev_1", doc.getString("deviceId"))
        assertEquals("act_1", doc.getString("challengeId"))
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 9 }), doc.getString("nonce"))
        assertEquals(1_760_000_000_000L, doc.getLong("ts"))
        assertEquals("payment", doc.getJSONObject("action").getString("type"))
        assertEquals(1250, doc.getJSONObject("action").getJSONObject("params").getInt("amountCents"))
        assertEquals(setOf("v", "deviceId", "challengeId", "nonce", "ts", "action"), doc.keySet())
        assertTrue(verifies(attester, "alias_1", signed))
        assertEquals(RequestHash.action(signed.signedData), hashSeen)
        assertEquals("tok", signed.playIntegrityToken)
    }

    @Test
    fun signsActionWithConfirmKeyAfterAuthentication() = runTest {
        val attester = FakeAttester(spki)
        val c = client(FakeApi(EnrollmentResult(Decision.ALLOW, "d", "dev_1")), attester, MemoryStore(), null)
        c.enroll()
        var prompted = 0
        val signed = c.signAction("payment", authenticator = { sig -> prompted++; sig })
        assertEquals(1, prompted)
        assertEquals(SigningKey.CONFIRM, signed.key)
        assertTrue(verifies(attester, "alias_2", signed))
        assertFalse(verifies(attester, "alias_1", signed))
    }

    @Test(expected = NotEnrolledException::class)
    fun signingRequiresEnrollment() = runTest {
        client(FakeApi(null), FakeAttester(spki), MemoryStore(), null).signAction("login")
    }

    @Test
    fun confirmSigningWithoutConfirmKeyFailsBeforeContactingServer() = runTest {
        val api = FakeApi(EnrollmentResult(Decision.ALLOW, "d", "dev_1"))
        val c = client(api, FakeAttester(spki, confirmSupported = false), MemoryStore(), null)
        c.enroll()
        try {
            c.signAction("payment", authenticator = { it })
            fail("expected exception")
        } catch (e: DeviceTrustException) {
            assertEquals(0, api.actionChallenges)
        }
    }

    @Test
    fun signalsAreSentAtEnrollmentAndSignedIntoActions() = runTest {
        val api = FakeApi(EnrollmentResult(Decision.ALLOW, "d", "dev_1"))
        val report = { JSONObject().put("v", 1).put("hook_frida", false) }
        val c = client(api, FakeAttester(spki), MemoryStore(), signals = { report() })
        c.enroll()
        assertEquals(1, api.sent!!.signals!!.getInt("v"))
        val signed = c.signAction("login")
        val doc = JSONObject(String(signed.signedData, Charsets.UTF_8))
        assertFalse(doc.getJSONObject("signals").getBoolean("hook_frida"))
    }

    @Test
    fun failingCollectorDoesNotBreakSigning() = runTest {
        val c = client(
            FakeApi(EnrollmentResult(Decision.ALLOW, "d", "dev_1")), FakeAttester(spki), MemoryStore(),
            signals = { throw IllegalStateException("boom") },
        )
        c.enroll()
        assertFalse(JSONObject(String(c.signAction("login").signedData, Charsets.UTF_8)).has("signals"))
    }

    @Test
    fun stepUpEnrollmentIsKept() = runTest {
        val store = MemoryStore()
        val attester = FakeAttester(spki)
        val result = client(FakeApi(EnrollmentResult(Decision.STEP_UP, "d", "dev_9")), attester, store, null).enroll()
        assertEquals(Decision.STEP_UP, result.decision)
        assertEquals("dev_9", store.value!!.deviceId)
        assertTrue("alias_1" in attester.live)
    }

    @Test
    fun resetDeletesKeysAndEnrollment() = runTest {
        val attester = FakeAttester(spki)
        val store = MemoryStore()
        val c = client(FakeApi(EnrollmentResult(Decision.ALLOW, "d", "dev_1")), attester, store, null)
        c.enroll()
        c.reset()
        assertTrue(attester.live.isEmpty())
        assertNull(store.value)
    }

    private fun verifies(attester: FakeAttester, alias: String, signed: SignedAction): Boolean =
        java.security.Signature.getInstance("SHA256withECDSA").run {
            initVerify(attester.keys.getValue(alias).public)
            update(signed.signedData)
            verify(signed.signature)
        }

    @Test
    fun missingPlayIntegrityStillEnrolls() = runTest {
        val api = FakeApi(EnrollmentResult(Decision.ALLOW, "dec_3", "dev_3"))
        client(api, FakeAttester(spki), MemoryStore()) { null }.enroll()
        assertNull(api.sent!!.playIntegrityToken)
    }

    @Test
    fun transportFailureDeletesBothKeys() = runTest {
        val attester = FakeAttester(spki)
        val store = MemoryStore()
        try {
            client(FakeApi(null, DeviceTrustException("down")), attester, store, null).enroll()
            fail("expected exception")
        } catch (e: DeviceTrustException) {
            // expected
        }
        assertTrue(attester.live.isEmpty())
        assertNull(store.value)
    }

    @Test
    fun chainIsSentLeafFirstAsBase64() {
        val encoded = JSONObject(
            TrustJson.encodeEnrollment(EnrollmentRequest("c", listOf(byteArrayOf(9), byteArrayOf(8)), "t", DEVICE)),
        ).getJSONArray("attestationChain")
        assertEquals(Base64.getEncoder().encodeToString(byteArrayOf(9)), encoded.getString(0))
        assertEquals(2, encoded.length())
    }
}

private val DEVICE = DeviceInfo("google", "shiba", "shiba", "Google", "Pixel 8")
