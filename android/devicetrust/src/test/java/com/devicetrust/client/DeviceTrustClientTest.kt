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

    @Test(expected = IllegalArgumentException::class)
    fun refusesCleartext() {
        HttpTrustApi("http://bank.example")
    }
}

class DeviceTrustClientTest {
    private val nonce = ByteArray(32) { 7 }
    private val spki = "attested-spki".toByteArray()

    private class FakeAttester(private val spki: ByteArray) : KeyAttester {
        val live = mutableSetOf<String>()
        var lastChallenge: ByteArray? = null
        override fun generate(alias: String, challenge: ByteArray): AttestedKey {
            lastChallenge = challenge
            live += alias
            return AttestedKey(alias, listOf(byteArrayOf(1), byteArrayOf(2)), spki, strongBox = false)
        }
        override fun delete(alias: String) {
            live -= alias
        }
    }

    private class MemoryStore(var value: Enrollment? = null) : EnrollmentStore {
        override fun load() = value
        override fun save(enrollment: Enrollment) { value = enrollment }
        override fun clear() { value = null }
    }

    private inner class FakeApi(private val result: EnrollmentResult?, private val error: Exception? = null) : TrustApi {
        var sent: EnrollmentRequest? = null
        override suspend fun createChallenge() = Challenge("ch_1", nonce, 0)
        override suspend fun enroll(request: EnrollmentRequest): EnrollmentResult {
            sent = request
            error?.let { throw it }
            return result!!
        }
    }

    private var aliasCounter = 0
    private fun client(api: TrustApi, attester: KeyAttester, store: EnrollmentStore, integrity: IntegrityTokenSource?) =
        DeviceTrustClient(api, attester, integrity, store, { DEVICE }, { "alias_${++aliasCounter}" })

    @Test
    fun allowKeepsNewKeyAndReplacesOldBinding() = runTest {
        val attester = FakeAttester(spki).apply { live += "old_alias" }
        val store = MemoryStore(Enrollment("dev_old", "old_alias"))
        var hashSeen: String? = null
        val api = FakeApi(EnrollmentResult(Decision.ALLOW, "dec_1", "dev_new"))

        val result = client(api, attester, store) { hash -> hashSeen = hash; "play-token" }.enroll()

        assertEquals(Decision.ALLOW, result.decision)
        assertEquals(Enrollment("dev_new", "alias_1"), store.value)
        assertEquals(setOf("alias_1"), attester.live)
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
    fun missingPlayIntegrityStillEnrolls() = runTest {
        val api = FakeApi(EnrollmentResult(Decision.ALLOW, "dec_3", "dev_3"))
        client(api, FakeAttester(spki), MemoryStore()) { null }.enroll()
        assertNull(api.sent!!.playIntegrityToken)
    }

    @Test
    fun transportFailureDeletesKey() = runTest {
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
