package com.devicetrust.scanner.scan

import androidx.fragment.app.FragmentActivity
import com.devicetrust.client.AndroidKeyAttester
import com.devicetrust.client.BiometricPromptAuthenticator
import com.devicetrust.scanner.attest.AUTH_BIOMETRIC
import com.devicetrust.scanner.attest.AUTH_PASSWORD
import com.devicetrust.scanner.attest.ChainVerifier
import com.devicetrust.scanner.attest.Check
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.util.UUID

/**
 * Demonstrates the biometric-bound confirm key: the secure hardware attests
 * that the key can only sign after a fresh strong-biometric authentication,
 * then the user approves a test payment and the signature is verified.
 */
class BiometricTest(private val activity: FragmentActivity) {
    private val attester = AndroidKeyAttester(activity)

    suspend fun run(): List<Check> {
        val checks = mutableListOf<Check>()
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val alias = "scanner_confirm_" + UUID.randomUUID()
        try {
            val key = withContext(Dispatchers.Default) { attester.generateConfirmKey(alias, challenge) }
            if (key == null) {
                checks += Check("confirm_key", "Biometric-bound key created", Check.Status.FAIL,
                    "no strong biometric enrolled or no screen lock set")
                return checks
            }
            checks += Check("confirm_key", "Biometric-bound key created", Check.Status.PASS,
                if (key.strongBox) "in StrongBox chip" else "in TEE")

            val roots = ChainVerifier.rootKeysFromJson(
                activity.assets.open("google_roots.json").use { it.readBytes().toString(Charsets.UTF_8) },
            )
            val report = ChainVerifier(roots, revokedSerials = emptySet()).verify(
                key.chain, challenge, activity.packageName, reportedIds = emptyMap(),
            )
            checks += report.checks.filter { it.id in setOf("google_root", "chain_signatures", "security_level") }
            val hw = report.keyDescription?.hardwareEnforced
            val auth = hw?.userAuthType ?: 0
            checks += Check(
                "auth_required", "Hardware enforces user authentication",
                if (hw != null && !hw.noAuthRequired) Check.Status.PASS else Check.Status.FAIL,
            )
            checks += Check(
                "biometric_only", "Only strong biometrics can unlock it",
                when {
                    auth and AUTH_BIOMETRIC != 0 && auth and AUTH_PASSWORD == 0 -> Check.Status.PASS
                    auth and AUTH_BIOMETRIC != 0 -> Check.Status.WARN
                    else -> Check.Status.FAIL
                },
                "userAuthType=$auth",
            )
            checks += Check(
                "per_use", "New authentication for every signature",
                if (hw?.authTimeout == null || hw.authTimeout == 0L) Check.Status.PASS else Check.Status.FAIL,
                hw?.authTimeout?.let { "timeout ${it}s" } ?: "no time window",
            )

            val payload = "test-payment:EUR:1.00:${UUID.randomUUID()}".toByteArray()
            val signer = withContext(Dispatchers.Default) { attester.signer(alias) }
            val unlocked = BiometricPromptAuthenticator(
                activity, title = "Confirm test payment", subtitle = "€1.00 to Test Merchant",
            ).authenticate(signer)
            val signature = withContext(Dispatchers.Default) {
                unlocked.update(payload)
                unlocked.sign()
            }
            val leaf = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(key.chain.first()))
            val valid = Signature.getInstance("SHA256withECDSA").run {
                initVerify(leaf.publicKey)
                update(payload)
                verify(signature)
            }
            checks += Check(
                "biometric_signature", "Approved payment signature verifies",
                if (valid) Check.Status.PASS else Check.Status.FAIL,
                "${signature.size}-byte ECDSA signature",
            )
        } catch (e: Exception) {
            checks += Check("biometric_error", "Biometric test", Check.Status.FAIL, e.message ?: e.javaClass.simpleName)
        } finally {
            attester.delete(alias)
        }
        return checks
    }
}
