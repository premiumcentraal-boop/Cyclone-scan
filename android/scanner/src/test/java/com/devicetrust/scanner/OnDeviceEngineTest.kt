package com.devicetrust.scanner

import com.devicetrust.scanner.attest.ChainVerifier
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.attest.Der
import com.devicetrust.scanner.attest.DerException
import com.devicetrust.scanner.attest.KEY_DESCRIPTION_OID
import com.devicetrust.scanner.attest.KeyDescriptionParser
import com.devicetrust.scanner.attest.SecurityLevel
import com.devicetrust.scanner.risk.LocalRisk
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.OffsetDateTime
import java.util.Base64
import java.util.Date

/** Real Google attestation chains, checked by the on-device engine (same fixtures as the server tests). */
class OnDeviceEngineTest {
    private val roots = ChainVerifier.rootKeysFromJson(File("src/main/assets/google_roots.json").readText())

    private fun chain(name: String): List<X509Certificate> =
        CertificateFactory.getInstance("X.509")
            .generateCertificates(javaClass.getResourceAsStream("/real/$name.pem"))
            .map { it as X509Certificate }

    private fun expected(name: String) = JSONObject(javaClass.getResourceAsStream("/real/$name.json")!!.bufferedReader().readText())

    /** "now" inside the intermediates' validity window, as when the fixture was captured. */
    private fun captureTime(certs: List<X509Certificate>): Date = certs.drop(1).maxOf { it.notBefore }

    private data class Run(val checks: Map<String, Check>, val report: com.devicetrust.scanner.attest.AttestationReport)

    private fun run(name: String, revoked: Set<String> = emptySet(), reported: Map<String, String>? = null): Run {
        val certs = chain(name)
        val exp = runCatching { expected(name) }.getOrNull()
        val hw = exp?.getJSONObject("hardwareEnforced")
        val ids = reported ?: listOf("brand", "device", "product", "manufacturer", "model").mapNotNull { f ->
            hw?.optString("attestationId" + f.replaceFirstChar(Char::uppercase))?.takeIf { it.isNotEmpty() }?.let { f to it }
        }.toMap()
        val pkg = exp?.getJSONObject("softwareEnforced")?.getJSONObject("attestationApplicationId")
            ?.getJSONArray("packages")?.getJSONObject(0)?.getString("name") ?: "unknown"
        val challenge = exp?.let { Base64.getDecoder().decode(it.getString("attestationChallenge")) } ?: ByteArray(0)
        val now = captureTime(certs)
        val report = ChainVerifier(roots, revoked) { now }.verify(certs.map { it.encoded }, challenge, pkg, ids, 1000)
        return Run(report.checks.associateBy { it.id }, report)
    }

    @Test
    fun genuineLockedDevicesPassEveryHardGate() {
        for (name in listOf("caiman_sdk36_TEE_EC_RKP", "caiman_sdk36_SB_EC_RKP", "sony-xperia10-iii_sdk33_TEE_EC",
            "frankel_sdk37_TEE_EC_2026")) {
            val r = run(name)
            assertTrue("$name: ${r.report.hardFailures.map { it.id to it.detail }}", r.report.hardFailures.isEmpty())
            assertEquals(Check.Status.PASS, r.checks.getValue("google_root").status)
            assertEquals(Check.Status.PASS, r.checks.getValue("bootloader").status)
        }
    }

    @Test
    fun parsedFieldsMatchGoogleExpectedValues() {
        val name = "caiman_sdk36_SB_EC_RKP"
        val kd = run(name).report.keyDescription!!
        val exp = expected(name)
        val hw = exp.getJSONObject("hardwareEnforced")
        assertEquals(SecurityLevel.valueOf(exp.getString("attestationSecurityLevel")), kd.attestationSecurityLevel)
        assertEquals(hw.getString("osPatchLevel").toInt(), kd.hardwareEnforced.osPatchLevel)
        assertEquals(hw.getString("attestationIdModel"), kd.hardwareEnforced.attestedIds["model"])
        assertEquals(hw.getJSONObject("rootOfTrust").getBoolean("deviceLocked"), kd.hardwareEnforced.rootOfTrust!!.deviceLocked)
        assertTrue(kd.hardwareEnforced.noAuthRequired)
    }

    @Test
    fun spoofedModelIsCaught() {
        val r = run("caiman_sdk36_TEE_EC_RKP", reported = mapOf("brand" to "google", "model" to "Pixel 10 Pro",
            "device" to "caiman", "product" to "caiman", "manufacturer" to "Google"))
        assertEquals(Check.Status.FAIL, r.checks.getValue("device_ids").status)
        assertTrue(r.checks.getValue("device_ids").detail.contains("model"))
    }

    @Test
    fun unlockedDevelopmentPhoneFails() {
        val r = run("akita_sdk34_TEE_EC_NONE")
        assertEquals(Check.Status.FAIL, r.checks.getValue("bootloader").status)
        assertEquals(Check.Status.FAIL, r.checks.getValue("verified_boot").status)
    }

    @Test
    fun softwareAttestationRootIsUntrusted() {
        assertEquals(Check.Status.FAIL, run("marlin_sdk29_TEE_EC_NONE").checks.getValue("google_root").status)
    }

    @Test
    fun revokedIntermediateFails() {
        val serial = chain("caiman_sdk36_TEE_EC_RKP")[1].serialNumber.toString(16)
        assertEquals(Check.Status.FAIL, run("caiman_sdk36_TEE_EC_RKP", revoked = setOf(serial)).checks.getValue("revocation").status)
    }

    @Test
    fun nonDerBooleanIsRejected() {
        val r = run("invalid_malformed_rot_device_locked")
        assertEquals(Check.Status.FAIL, r.checks.getValue("ext_parse").status)
        assertNull(r.report.keyDescription)
    }

    @Test
    fun realPasswordOnlyKeyReportsItsAuthRules() {
        val ext = chain("akita_sdk34_TEE_RSA_NONE_USERAUTH")[0].getExtensionValue(KEY_DESCRIPTION_OID)
        val hw = KeyDescriptionParser.parse(ChainVerifier.unwrapOctetString(ext)).hardwareEnforced
        assertFalse(hw.noAuthRequired)
        assertEquals(1, hw.userAuthType)
        assertEquals(2147483647L, hw.authTimeout)
    }

    @Test
    fun revocationListParsing() {
        val set = ChainVerifier.parseRevocations("""{"entries":{"00ABC":{"status":"REVOKED"},"1f43":{"status":"REVOKED"}}}""")
        assertEquals(setOf("abc", "1f43"), set)
    }

    @Test(expected = DerException::class)
    fun derRejectsTrailingData() {
        Der.readSingle(byteArrayOf(0x30, 0x00, 0x00))
    }

    @Test
    fun patchAge() {
        val now = Date.from(OffsetDateTime.parse("2026-10-13T00:00:00Z").toInstant())
        assertEquals(1, ChainVerifier.patchAgeMonths(202609, now))
        assertEquals(1, ChainVerifier.patchAgeMonths(20260905, now))
        assertNull(ChainVerifier.patchAgeMonths(202613, now))
    }
}

/** The on-device risk engine must agree with the server engine on every shared vector. */
class RiskParityTest {
    @Test
    fun matchesServerVectors() {
        val doc = JSONObject(File("../../testvectors/risk_vectors.json").readText())
        val now = Date.from(OffsetDateTime.parse(doc.getString("now")).toInstant())
        val trusted = doc.getJSONArray("trusted_digests").let { a -> (0 until a.length()).map { a.getString(it) }.toSet() }
        assertEquals(LocalRisk.ALLOW_BELOW, doc.getJSONObject("thresholds").getInt("allow_below"))
        assertEquals(LocalRisk.BLOCK_AT, doc.getJSONObject("thresholds").getInt("block_at"))
        val cases = doc.getJSONArray("cases")
        assertTrue(cases.length() >= 30)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val ev = c.getJSONObject("evidence")
            val result = LocalRisk.assess(
                c.getJSONObject("signals"),
                LocalRisk.Evidence(ev.optInt("os_patch_level"), ev.optString("attestation_security_level")),
                trusted, now,
            )
            val exp = c.getJSONObject("expected")
            val expFactors = exp.getJSONArray("factors").let { a ->
                (0 until a.length()).map { a.getJSONArray(it).let { f -> f.getString(0) to f.getInt(1) } }
            }
            val name = c.getString("name")
            assertEquals(name, exp.getInt("score"), result.score)
            assertEquals(name, exp.getString("band"), result.band)
            assertEquals(name, expFactors, result.factors)
        }
    }

    @Test
    fun everyWeightHasAnExplanation() {
        LocalRisk.WEIGHTS.keys.forEach { assertTrue(it, it in LocalRisk.DESCRIPTIONS) }
    }
}
