package com.devicetrust.scanner

import com.devicetrust.scanner.attest.ChainVerifier
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.attest.SecurityLevel
import com.devicetrust.scanner.risk.LocalRisk
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

/** Run 15: the on-device verifier must reach the server's outcomes on testvectors/attestation_vectors.json. */
class AttestationVectorsTest {
    private val roots = ChainVerifier.rootKeysFromJson(File("src/main/assets/google_roots.json").readText())

    private fun chain(name: String): List<X509Certificate> =
        CertificateFactory.getInstance("X.509")
            .generateCertificates(javaClass.getResourceAsStream("/real/$name.pem"))
            .map { it as X509Certificate }

    private fun expected(name: String) =
        JSONObject(javaClass.getResourceAsStream("/real/$name.json")!!.bufferedReader().readText())

    private fun verify(name: String, now: Date): Map<String, Check> {
        val exp = expected(name)
        val hw = exp.getJSONObject("hardwareEnforced")
        val ids = listOf("brand", "device", "product", "manufacturer", "model").mapNotNull { f ->
            hw.optString("attestationId" + f.replaceFirstChar(Char::uppercase)).takeIf { it.isNotEmpty() }?.let { f to it }
        }.toMap()
        val pkg = exp.getJSONObject("softwareEnforced").getJSONObject("attestationApplicationId")
            .getJSONArray("packages").getJSONObject(0).getString("name")
        val challenge = Base64.getDecoder().decode(exp.getString("attestationChallenge"))
        val report = ChainVerifier(roots, emptySet()) { now }
            .verify(chain(name).map { it.encoded }, challenge, pkg, ids, 1000)
        return report.checks.associateBy { it.id } + ("__chainType" to Check("__chainType", report.chainType ?: "null", Check.Status.INFO))
    }

    @Test
    fun matchesServerVerifierOutcomes() {
        val cases = JSONObject(File("../../testvectors/attestation_vectors.json").readText()).getJSONArray("cases")
        assertTrue(cases.length() >= 14)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val e = c.getJSONObject("expected")
            val label = c.getString("name") + "@" + c.getString("when")
            val checks = verify(c.getString("name"), Date(c.getLong("now_ms")))
            assertEquals(label, e.getBoolean("root_untrusted"), checks.getValue("google_root").status == Check.Status.FAIL)
            if (e.getBoolean("root_untrusted")) {
                assertEquals(label, "null", checks.getValue("__chainType").label)
                continue
            }
            assertEquals(label, if (e.isNull("chain_type")) "null" else e.getString("chain_type"), checks.getValue("__chainType").label)
            assertEquals(label, e.getBoolean("cert_expired"), checks.getValue("validity").status == Check.Status.FAIL)
            assertEquals(label, e.getBoolean("legacy_exempt"), checks.getValue("validity").detail.contains("legacy"))
            assertEquals(label, e.getBoolean("security_mismatch"), checks["security_chain"]?.status == Check.Status.FAIL)
            assertEquals(label, e.getBoolean("provisioning_misplaced"), checks["provisioning_info"]?.status == Check.Status.FAIL)
        }
    }

    @Test
    fun securityLevelRuleMatchesReference() {
        val sb = SecurityLevel.STRONG_BOX
        val tee = SecurityLevel.TRUSTED_ENVIRONMENT
        val sw = SecurityLevel.SOFTWARE
        assertTrue(ChainVerifier.securityLevelMatchesChain(sb, sb))
        assertFalse(ChainVerifier.securityLevelMatchesChain(sb, null))
        assertFalse(ChainVerifier.securityLevelMatchesChain(sb, tee))
        assertTrue(ChainVerifier.securityLevelMatchesChain(tee, null))
        assertTrue(ChainVerifier.securityLevelMatchesChain(tee, tee))
        assertFalse(ChainVerifier.securityLevelMatchesChain(tee, sb))
        assertTrue(ChainVerifier.securityLevelMatchesChain(sw, null))
        assertFalse(ChainVerifier.securityLevelMatchesChain(sw, tee))
    }

    @Test
    fun rkpClaimsComeFromTheAttestationCert() {
        assertEquals(sbClaim("caiman_sdk36_SB_EC_RKP"), SecurityLevel.STRONG_BOX)
        assertEquals(sbClaim("caiman_sdk36_TEE_EC_RKP"), SecurityLevel.TRUSTED_ENVIRONMENT)
        assertEquals(null, ChainVerifier.chainSecurityClaim(chain("sony-xperia10-iii_sdk33_TEE_EC"), ChainVerifier.CHAIN_FACTORY))
        assertEquals("f92009e853b6b045", ChainVerifier.names(chain("sony-xperia10-iii_sdk33_TEE_EC").last())["SERIALNUMBER"])
    }

    private fun sbClaim(name: String) = ChainVerifier.chainSecurityClaim(chain(name), ChainVerifier.CHAIN_RKP)

    @Test
    fun unrecognizedChainKeepsNotRkpFactors() {
        val ev = LocalRisk.Evidence(osPatchLevel = 202609, securityLevel = "STRONG_BOX", attestedBrand = "google",
            attestedModel = "Pixel 9", osVersion = 160000)
        fun factors(t: String) = LocalRisk.assess(null, ev.copy(chainType = t), emptySet()).factors
        assertEquals(factors("FACTORY"), factors("UNRECOGNIZED"))
        assertFalse(factors("RKP").any { it.first == "attestation_not_rkp_on_rkp_model" })
    }
}
