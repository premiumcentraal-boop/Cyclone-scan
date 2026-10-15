package com.devicetrust.client

import com.devicetrust.client.signals.AccessibilityServiceRef
import com.devicetrust.client.signals.DeviceSignals
import com.devicetrust.client.signals.FakeProbe
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Run 17: scan / key-rotation transcripts, the wire format and the client flows. */
class ScanEvidenceTest {
    private val challenge = Challenge("c".repeat(128), ByteArray(32) { it.toByte() }, 120)
    private val maxDevice = DeviceInfo("b".repeat(128), "d".repeat(128), "p".repeat(128), "m".repeat(128), "x".repeat(128))
    private val chain = List(10) { ByteArray(600) { i -> (i + it).toByte() } }

    @Test
    fun requestHashesMatchServerVectors() {
        // device_trust.scan_evidence.request_hash("scan" / "key-rotation", b'{"v":1}')
        assertEquals("ZzcneE3Zlk5883cVVpGSW56Nau7I-DFmhd8JhQsXDCk", RequestHash.scanEvidence("{\"v\":1}".toByteArray()))
        assertEquals("dZL8pKhvSojp1exgmXcwnSL2mKbDRmRwcpd-BrUud_A", RequestHash.keyRotation("{\"v\":1}".toByteArray()))
    }

    @Test
    fun scanTranscriptHasExactlyTheDocumentedFields() {
        val doc = JSONObject(String(ScanEvidence.scan("dev_1", challenge, 5L, chain, DEVICE, null), Charsets.UTF_8))
        assertEquals(setOf("v", "purpose", "deviceId", "challengeId", "nonce", "ts", "freshChainSha256", "device", "signals"),
            doc.keySet())
        assertEquals("scan", doc.getString("purpose"))
        assertEquals(10, doc.getJSONArray("freshChainSha256").length())
        assertTrue(doc.isNull("signals"))
        val none = JSONObject(String(ScanEvidence.scan("dev_1", challenge, 5L, null, DEVICE, null), Charsets.UTF_8))
        assertTrue(none.isNull("freshChainSha256"))
    }

    @Test
    fun rotationTranscriptHasExactlyTheDocumentedFields() {
        val doc = JSONObject(String(ScanEvidence.keyRotation("dev_1", challenge, 5L, chain, null, DEVICE), Charsets.UTF_8))
        assertEquals(setOf("v", "purpose", "deviceId", "challengeId", "nonce", "ts", "newChainSha256",
            "newConfirmChainSha256", "device"), doc.keySet())
        assertEquals("key-rotation", doc.getString("purpose"))
        assertTrue(doc.isNull("newConfirmChainSha256"))
    }

    /** CI re-checks these with the server's strict parser (tools/check_scan_fixtures.py). */
    @Test
    fun writesMaximumSizeFixturesForTheServerParser() {
        val signals = DeviceSignals(FakeProbe().apply {
            files += setOf("/system/xbin/su", "/data/adb/modules", "/dev/qemu_pipe")
            packages += DeviceSignals.ROOT_APPS + DeviceSignals.REMOTE_ACCESS_APPS.values.flatten()
            texts["/proc/self/maps"] = "frida-agent zygisk liblspd"
            installer = "com.other.store"
            a11y = DeviceSignals.REMOTE_ACCESS_APPS.values.flatten().map { AccessibilityServiceRef(it, false) }
        }).collect()
        val out = File("build").apply { mkdirs() }
        val scan = ScanEvidence.scan("d".repeat(128), challenge, 1_760_000_000_000L, chain, maxDevice, signals)
        val rotation = ScanEvidence.keyRotation("d".repeat(128), challenge, 1_760_000_000_000L, chain, chain, maxDevice)
        assertTrue("scan transcript is ${scan.size} bytes", scan.size <= 32 * 1024)
        File(out, "scan-transcript-detected.json").writeBytes(scan)
        File(out, "key-rotation-transcript.json").writeBytes(rotation)
    }

    @Test
    fun parsesAndLabelsAVerifiedScan() {
        val body = """{"decision":"ALLOW","decisionId":"dec_1","verifiedAt":1000,"freshUntil":301000,
            "policy":{"version":"beta","digest":"0123456789abcdef","verifierRuleset":"run15-attestation-v1"},
            "evidence":{"deviceKeySignature":"VERIFIED","freshAttestation":"VERIFIED","playIntegrity":"VERIFIED","clientSignals":"SIGNED"},
            "coverage":{"DETECTED":1,"NOT_DETECTED":20},
            "history":{"snapshots":2,"previousAt":1.5,"previousSource":"enrollment","compared":true,
                       "changes":[{"code":"FRESH_KEY_AUTHORIZED","level":"INFO","field":"leaf_spki_sha256"}]}}"""
        val scan = TrustJson.parseScan(body).copy(playRequested = true)
        assertEquals(Decision.ALLOW, scan.decision)
        assertEquals(ScanPolicy("beta", "0123456789abcdef", "run15-attestation-v1"), scan.policy)
        assertEquals(20, scan.coverage!!["NOT_DETECTED"])
        assertEquals("FRESH_KEY_AUTHORIZED", scan.history!!.changes.single().code)
        assertNull(scan.diagnostics)
        assertEquals(ScanLabel.VERIFIED_FRESH, scan.label(2_000))
        assertEquals(ScanLabel.VERIFIED_EXPIRED, scan.label(301_001))
        assertEquals(ScanLabel.REJECTED, scan.copy(decision = Decision.BLOCK).label(2_000))
        val noPlay = scan.copy(playRequested = false, evidence = scan.evidence.copy(playIntegrity = EvidenceStatus.NOT_PROVIDED))
        assertEquals(ScanLabel.VERIFIED_PARTIAL, noPlay.label(2_000))
        assertEquals(listOf("Play Integrity not requested (no Cloud project configured)"), noPlay.partialBecause())
        val noFresh = scan.copy(evidence = scan.evidence.copy(freshAttestation = EvidenceStatus.NOT_PROVIDED))
        assertEquals(ScanLabel.VERIFIED_PARTIAL, noFresh.label(2_000))
        val badSignature = scan.copy(evidence = scan.evidence.copy(deviceKeySignature = EvidenceStatus.FAILED))
        assertEquals(ScanLabel.REJECTED, badSignature.label(2_000))
        assertEquals(ScanLabel.UNAVAILABLE, ServerScan.Unavailable(UnavailableReason.NETWORK).label(0))
    }

    @Test
    fun malformedScanResponsesAreNeverVerified() {
        val bad = listOf(
            """{"decision":"ALLOW","decisionId":"d"}""",
            """{"decision":"MAYBE","decisionId":"d","verifiedAt":1,"freshUntil":2,"policy":{"version":"","digest":"x","verifierRuleset":"r"},
               "evidence":{"deviceKeySignature":"VERIFIED","freshAttestation":"VERIFIED","playIntegrity":"VERIFIED","clientSignals":"SIGNED"}}""",
            """{"decision":"ALLOW","decisionId":"d","verifiedAt":1,"freshUntil":2,"policy":{"version":"","digest":"x","verifierRuleset":"r"},
               "evidence":{"deviceKeySignature":"PROBABLY","freshAttestation":"VERIFIED","playIntegrity":"VERIFIED","clientSignals":"SIGNED"}}""",
            """{"decision":"ALLOW","decisionId":"d","verifiedAt":5,"freshUntil":2,"policy":{"version":"","digest":"x","verifierRuleset":"r"},
               "evidence":{"deviceKeySignature":"VERIFIED","freshAttestation":"VERIFIED","playIntegrity":"VERIFIED","clientSignals":"SIGNED"}}""",
            "not json",
        )
        for (body in bad) {
            try {
                TrustJson.parseScan(body)
                fail("accepted: $body")
            } catch (e: MalformedResponseException) {
                // expected
            }
        }
    }

    @Test
    fun encodesScanAndRotationRequests() {
        val scan = JSONObject(TrustJson.encodeScan(ScanRequest("dev", "ch", byteArrayOf(1), byteArrayOf(2), null, null)))
        assertEquals(setOf("deviceId", "challengeId", "scanData", "signature"), scan.keySet())
        val rotation = JSONObject(TrustJson.encodeKeyRotation(
            KeyRotationRequest("dev", "ch", byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), listOf(byteArrayOf(4)), null)))
        assertEquals(setOf("deviceId", "challengeId", "rotationData", "oldKeySignature", "newKeySignature",
            "newAttestationChain"), rotation.keySet())
        val withPlay = JSONObject(TrustJson.encodeKeyRotation(
            KeyRotationRequest("dev", "ch", byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), listOf(byteArrayOf(4)), null, "tok")))
        assertEquals("tok", withPlay.getString("playIntegrityToken"))
        val challengeBody = JSONObject(TrustJson.encodeDeviceChallengeRequest("dev", "scan"))
        assertEquals(setOf("deviceId", "purpose"), challengeBody.keySet())
        assertEquals("scan", challengeBody.getString("purpose"))
        val result = TrustJson.parseKeyRotation("""{"decision":"ALLOW","decisionId":"d","rotated":true,"hasConfirmKey":false}""")
        assertEquals(KeyRotationResult(Decision.ALLOW, "d", true, false), result)
    }
}

class VerifiedScanClientTest {
    private class Attester(private val confirm: Boolean = true) : KeyAttester {
        val keys = mutableMapOf<String, KeyPair>()
        val generated = mutableListOf<String>()
        val challenges = mutableListOf<ByteArray>()
        var failGenerate = false
        override fun generate(alias: String, challenge: ByteArray): AttestedKey {
            if (failGenerate) throw DeviceTrustException("no more keys")
            challenges += challenge
            generated += alias
            keys[alias] = ec()
            return AttestedKey(alias, listOf(alias.toByteArray(), byteArrayOf(2)), alias.toByteArray(), false)
        }
        override fun generateConfirmKey(alias: String, challenge: ByteArray): AttestedKey? {
            if (!confirm) return null
            keys[alias] = ec()
            return AttestedKey(alias, listOf(byteArrayOf(3)), byteArrayOf(3), false)
        }
        override fun signer(alias: String): Signature =
            Signature.getInstance("SHA256withECDSA").apply { initSign((keys[alias] ?: throw NotEnrolledException()).private) }
        override fun delete(alias: String) { keys.remove(alias) }
        private fun ec() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    }

    private class Store(var value: Enrollment?) : EnrollmentStore {
        override fun load() = value
        override fun save(enrollment: Enrollment) { value = enrollment }
        override fun clear() { value = null }
    }

    private class Api(
        val scanResult: (ScanRequest) -> ServerScan.Verified = { verified() },
        val rotation: (KeyRotationRequest) -> KeyRotationResult = { KeyRotationResult(Decision.ALLOW, "d", true, true) },
        val challengeError: Exception? = null,
    ) : TrustApi {
        val purposes = mutableListOf<String>()
        var scan: ScanRequest? = null
        var rotationRequest: KeyRotationRequest? = null
        override suspend fun createChallenge() = error("not used")
        override suspend fun enroll(request: EnrollmentRequest) = error("not used")
        override suspend fun createActionChallenge(deviceId: String) = error("not used")
        override suspend fun verifyAction(action: SignedAction) = error("not used")
        override suspend fun createDeviceChallenge(deviceId: String, purpose: String): Challenge {
            challengeError?.let { throw it }
            purposes += purpose
            return Challenge("ch_$purpose", ByteArray(32) { 5 }, 0)
        }
        override suspend fun verifyScan(request: ScanRequest): ServerScan.Verified { scan = request; return scanResult(request) }
        override suspend fun rotateKey(request: KeyRotationRequest): KeyRotationResult { rotationRequest = request; return rotation(request) }
    }

    private var n = 0
    private fun client(api: TrustApi, attester: KeyAttester, store: EnrollmentStore, integrity: IntegrityTokenSource? = null,
                       signals: com.devicetrust.client.signals.SignalCollector? = null) =
        DeviceTrustClient(api, attester, integrity, store, { DEVICE }, { "a${++n}" }, { 1_760_000_000_000L }, signals)

    private fun enrolled(attester: Attester) = Store(Enrollment("dev_1", "enrolled", "confirm")).also {
        attester.generate("enrolled", ByteArray(1)); attester.generateConfirmKey("confirm", ByteArray(1))
        attester.generated.clear(); attester.challenges.clear()
    }

    private fun verifies(attester: Attester, alias: String, data: ByteArray, sig: ByteArray) =
        Signature.getInstance("SHA256withECDSA").run { initVerify(attester.keys.getValue(alias).public); update(data); verify(sig) }

    @Test
    fun scanSignsWithEnrolledKeyAndDeletesEphemeralKey() = runTest {
        val attester = Attester()
        val store = enrolled(attester)
        val api = Api()
        var hash: String? = null
        val result = client(api, attester, store, integrity = { h -> hash = h; "tok" },
            signals = { JSONObject().put("v", 1) }).verifiedScan()
        assertTrue(result is ServerScan.Verified && result.playRequested)
        val sent = api.scan!!
        assertEquals(listOf("scan"), api.purposes)
        assertTrue(verifies(attester, "enrolled", sent.scanData, sent.signature))
        assertEquals(RequestHash.scanEvidence(sent.scanData), hash)
        assertEquals("tok", sent.playIntegrityToken)
        // The fresh key used the scan nonce and is gone afterwards; enrolled keys remain.
        assertTrue(ByteArray(32) { 5 }.contentEquals(attester.challenges.single()))
        assertEquals(setOf("enrolled", "confirm"), attester.keys.keys)
        val doc = JSONObject(String(sent.scanData, Charsets.UTF_8))
        assertEquals(sent.freshAttestationChain!!.size, doc.getJSONArray("freshChainSha256").length())
        assertEquals(1, doc.getJSONObject("signals").getInt("v"))
        assertEquals(store.value, Enrollment("dev_1", "enrolled", "confirm"))
    }

    @Test
    fun ephemeralKeyIsDeletedWhenTheServerFails() = runTest {
        val attester = Attester()
        val api = Api(scanResult = { throw HttpStatusException("/v1/scans/verify", 500) })
        val result = client(api, attester, enrolled(attester)).verifiedScan()
        assertEquals(ServerScan.Unavailable(UnavailableReason.SERVER_ERROR, "HTTP 500"), result)
        assertEquals(setOf("enrolled", "confirm"), attester.keys.keys)
    }

    @Test
    fun remoteFailuresAreUnavailableNeverVerified() = runTest {
        val cases = mapOf(
            NotEnrolledException() to UnavailableReason.DEVICE_NOT_ACTIVE,
            DeviceTrustException("trust API unreachable") to UnavailableReason.NETWORK,
            MalformedResponseException("bad") to UnavailableReason.MALFORMED_RESPONSE,
            UnsupportedOperationException("old transport") to UnavailableReason.UNSUPPORTED_TRANSPORT,
        )
        for ((error, reason) in cases) {
            val attester = Attester()
            val result = client(Api(challengeError = error), attester, enrolled(attester)).verifiedScan()
            assertTrue("$error", result is ServerScan.Unavailable && result.reason == reason)
            assertEquals(ScanLabel.UNAVAILABLE, result.label(0))
        }
        assertEquals(ServerScan.Unavailable(UnavailableReason.NOT_ENROLLED), client(Api(), Attester(), Store(null)).verifiedScan())
    }

    @Test
    fun lostEnrolledKeyIsReportedAsKeyUnavailable() = runTest {
        val attester = Attester()
        val store = enrolled(attester)
        attester.delete("enrolled")
        assertEquals(ServerScan.Unavailable(UnavailableReason.KEY_UNAVAILABLE), client(Api(), attester, store).verifiedScan())
    }

    @Test
    fun deviceThatCannotMakeAFreshKeyStillAsksTheServer() = runTest {
        val attester = Attester()
        val store = enrolled(attester)
        attester.failGenerate = true
        val api = Api()
        client(api, attester, store).verifiedScan()
        assertNull(api.scan!!.freshAttestationChain)
        assertTrue(JSONObject(String(api.scan!!.scanData, Charsets.UTF_8)).isNull("freshChainSha256"))
    }

    @Test
    fun throwingPlaySourceIsNotFatal() = runTest {
        val attester = Attester()
        val api = Api()
        val result = client(api, attester, enrolled(attester), integrity = { throw IllegalStateException("no play") }).verifiedScan()
        assertTrue(result is ServerScan.Verified)
        assertNull(api.scan!!.playIntegrityToken)
    }

    @Test
    fun rotationSwitchesKeysOnlyWhenRotated() = runTest {
        val attester = Attester()
        val store = enrolled(attester)
        val api = Api()
        val result = client(api, attester, store).rotateKeys()
        assertTrue(result.rotated)
        val sent = api.rotationRequest!!
        assertEquals(listOf("key-rotation"), api.purposes)
        assertEquals(Enrollment("dev_1", "a1", "a2"), store.value)
        assertEquals(setOf("a1", "a2"), attester.keys.keys)   // old device and confirm keys deleted
        assertFalse(attester.keys.containsKey("enrolled"))
        // New-key possession over the exact transcript bytes (old-key signature: next test).
        val doc = JSONObject(String(sent.rotationData, Charsets.UTF_8))
        assertEquals("key-rotation", doc.getString("purpose"))
        assertTrue(verifies(attester, "a1", sent.rotationData, sent.newKeySignature))
    }

    @Test
    fun rotationCarriesAPlayTokenBoundToTheRotationTranscript() = runTest {
        val attester = Attester()
        val api = Api()
        var hash: String? = null
        client(api, attester, enrolled(attester), integrity = { h -> hash = h; "tok" }).rotateKeys()
        val sent = api.rotationRequest!!
        assertEquals("tok", sent.playIntegrityToken)
        assertEquals(RequestHash.keyRotation(sent.rotationData), hash)
        // Without a configured Play source no token is sent (the server decides whether that blocks).
        val api2 = Api()
        val attester2 = Attester()
        client(api2, attester2, enrolled(attester2)).rotateKeys()
        assertEquals(null, api2.rotationRequest!!.playIntegrityToken)
    }

    @Test
    fun refusedRotationKeepsOldKeysAndDeletesNewOnes() = runTest {
        for (answer in listOf(KeyRotationResult(Decision.STEP_UP, "d", false, null),
                              KeyRotationResult(Decision.BLOCK, "d", false, null))) {
            val attester = Attester()
            val store = enrolled(attester)
            client(Api(rotation = { answer }), attester, store).rotateKeys()
            assertEquals(Enrollment("dev_1", "enrolled", "confirm"), store.value)
            assertEquals(setOf("enrolled", "confirm"), attester.keys.keys)
        }
        val attester = Attester()
        val store = enrolled(attester)
        try {
            client(Api(rotation = { throw DeviceTrustException("lost") }), attester, store).rotateKeys()
            fail("expected exception")
        } catch (e: DeviceTrustException) {
            // expected: the old keys are kept
        }
        assertEquals(setOf("enrolled", "confirm"), attester.keys.keys)
    }

    @Test
    fun rotationOldKeySignatureVerifies() = runTest {
        val attester = Attester()
        val store = enrolled(attester)
        val oldPublic = attester.keys.getValue("enrolled").public
        val api = Api()
        client(api, attester, store).rotateKeys(withConfirmKey = false)
        val sent = api.rotationRequest!!
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(oldPublic); update(sent.rotationData); verify(sent.oldKeySignature)
        })
        assertNull(sent.newConfirmKeyChain)
    }

    private companion object {
        val DEVICE = DeviceInfo("google", "shiba", "shiba", "Google", "Pixel 8")
        fun verified() = ServerScan.Verified(
            Decision.ALLOW, "dec", 1, 2, ScanPolicy("", "0", "r"),
            ScanEvidenceStatus(EvidenceStatus.VERIFIED, EvidenceStatus.VERIFIED, EvidenceStatus.VERIFIED, EvidenceStatus.SIGNED),
            null, null,
        )
    }
}

private val DEVICE = DeviceInfo("google", "shiba", "shiba", "Google", "Pixel 8")
