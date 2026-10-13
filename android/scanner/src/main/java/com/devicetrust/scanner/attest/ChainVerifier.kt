package com.devicetrust.scanner.attest

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Calendar
import java.util.Date
import java.util.TimeZone

/** One check shown in the report: passed / failed / not applicable, with detail text. */
data class Check(val id: String, val label: String, val status: Status, val detail: String = "") {
    enum class Status { PASS, FAIL, WARN, INFO }
}

/** Everything learned from one attestation chain (privacy-safe: no serial/IMEI). */
class AttestationReport(
    val checks: List<Check>,
    val keyDescription: KeyDescription?,
    val chainLength: Int,
    val rootSubject: String?,
    val revocationChecked: Boolean,
) {
    val hardFailures: List<Check> get() = checks.filter { it.status == Check.Status.FAIL }
}

/**
 * On-device port of the server's AttestationVerifier, for the scanner's local
 * mode. A real deployment makes this decision on the server: an attacker who
 * controls the phone could also patch this code. Here it shows what the
 * server would conclude.
 */
class ChainVerifier(
    private val trustedRootKeys: List<ByteArray>,
    private val revokedSerials: Set<String>?,
    private val clock: () -> Date = ::Date,
) {
    fun verify(
        chainDer: List<ByteArray>,
        expectedChallenge: ByteArray,
        expectedPackage: String,
        reportedIds: Map<String, String>,
        maxPatchAgeMonths: Int = 12,
    ): AttestationReport {
        val checks = mutableListOf<Check>()
        val cf = CertificateFactory.getInstance("X.509")
        val certs = try {
            chainDer.map { cf.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }
        } catch (e: Exception) {
            checks += Check("chain_parse", "Certificate chain readable", Check.Status.FAIL, e.javaClass.simpleName)
            return AttestationReport(checks, null, chainDer.size, null, false)
        }
        checks += Check("chain_parse", "Certificate chain readable", Check.Status.PASS, "${certs.size} certificates")
        if (certs.size < 2) {
            checks += Check("chain_length", "Chain has a root", Check.Status.FAIL, "only ${certs.size} certificate")
            return AttestationReport(checks, null, certs.size, null, false)
        }

        val extPositions = certs.indices.filter { certs[it].getExtensionValue(KEY_DESCRIPTION_OID) != null }
        checks += when (extPositions) {
            listOf(0) -> Check("ext_leaf_only", "Attestation data only in leaf", Check.Status.PASS)
            emptyList<Int>() -> Check("ext_leaf_only", "Attestation data present", Check.Status.FAIL, "no KeyDescription")
            else -> Check("ext_leaf_only", "Attestation data only in leaf", Check.Status.FAIL, "forged-leaf pattern")
        }

        val sigOk = certs.zipWithNext().all { (child, issuer) ->
            runCatching { child.verify(issuer.publicKey) }.isSuccess &&
                child.issuerX500Principal == issuer.subjectX500Principal
        }
        checks += Check("chain_signatures", "Chain signatures valid", if (sigOk) Check.Status.PASS else Check.Status.FAIL)

        val root = certs.last()
        val rootTrusted = trustedRootKeys.any { it.contentEquals(root.publicKey.encoded) }
        checks += Check(
            "google_root", "Rooted in Google hardware attestation CA",
            if (rootTrusted) Check.Status.PASS else Check.Status.FAIL,
            if (rootTrusted) shortName(root) else "untrusted root: ${shortName(root)}",
        )

        val now = clock()
        val expired = certs.drop(1).any { now.before(it.notBefore) || now.after(it.notAfter) }
        checks += Check("validity", "Intermediate certificates in date", if (expired) Check.Status.FAIL else Check.Status.PASS)

        if (revokedSerials == null) {
            checks += Check("revocation", "Not on Google revocation list", Check.Status.WARN, "list unavailable (offline?)")
        } else {
            val revoked = certs.any { it.serialNumber.toString(16) in revokedSerials }
            checks += Check(
                "revocation", "Not on Google revocation list",
                if (revoked) Check.Status.FAIL else Check.Status.PASS,
                if (revoked) "a certificate in this chain is REVOKED (leaked keybox?)" else "${revokedSerials.size} revoked entries checked",
            )
        }

        val kd = try {
            KeyDescriptionParser.parse(unwrapOctetString(certs[0].getExtensionValue(KEY_DESCRIPTION_OID)!!))
        } catch (e: Exception) {
            checks += Check("ext_parse", "Attestation data well-formed", Check.Status.FAIL, e.message.orEmpty())
            return AttestationReport(checks, null, certs.size, shortName(root), revokedSerials != null)
        }
        contentChecks(kd, expectedChallenge, expectedPackage, reportedIds, maxPatchAgeMonths, now, checks)
        return AttestationReport(checks, kd, certs.size, shortName(root), revokedSerials != null)
    }

    private fun contentChecks(
        kd: KeyDescription,
        challenge: ByteArray,
        pkg: String,
        reported: Map<String, String>,
        maxPatchAge: Int,
        now: Date,
        checks: MutableList<Check>,
    ) {
        checks += Check("challenge", "Fresh challenge bound", if (MessageDigest.isEqual(kd.challenge, challenge)) Check.Status.PASS else Check.Status.FAIL)

        val level = minOf(kd.attestationSecurityLevel, kd.keyMintSecurityLevel)
        checks += Check(
            "security_level", "Key in secure hardware",
            if (level >= SecurityLevel.TRUSTED_ENVIRONMENT) Check.Status.PASS else Check.Status.FAIL,
            level.label(),
        )
        checks += Check(
            "strongbox", "StrongBox secure chip",
            if (kd.attestationSecurityLevel == SecurityLevel.STRONG_BOX) Check.Status.PASS else Check.Status.INFO,
            if (kd.attestationSecurityLevel == SecurityLevel.STRONG_BOX) "dedicated security chip" else "TEE only (normal for most phones)",
        )

        val hw = kd.hardwareEnforced
        val rot = hw.rootOfTrust
        if (rot == null) {
            checks += Check("root_of_trust", "Boot state attested", Check.Status.FAIL, "missing")
        } else {
            checks += Check(
                "bootloader", "Bootloader locked",
                if (rot.deviceLocked) Check.Status.PASS else Check.Status.FAIL,
                if (rot.deviceLocked) "locked" else "UNLOCKED",
            )
            checks += Check(
                "verified_boot", "Verified boot",
                when (rot.verifiedBootState) {
                    VerifiedBootState.VERIFIED -> Check.Status.PASS
                    VerifiedBootState.SELF_SIGNED -> Check.Status.WARN
                    else -> Check.Status.FAIL
                },
                when (rot.verifiedBootState) {
                    VerifiedBootState.VERIFIED -> "official OS"
                    VerifiedBootState.SELF_SIGNED -> "custom OS signed by its own key (e.g. GrapheneOS)"
                    else -> rot.verifiedBootState.name
                },
            )
        }
        checks += Check(
            "key_origin", "Key generated inside hardware",
            if (hw.origin == 0) Check.Status.PASS else Check.Status.FAIL,
        )

        val app = hw.appId ?: kd.softwareEnforced.appId
        checks += Check(
            "app_identity", "Attested app identity",
            if (app != null && pkg in app.packageNames) Check.Status.PASS else Check.Status.FAIL,
            app?.packageNames?.joinToString().orEmpty(),
        )

        val patch = hw.osPatchLevel
        val age = patch?.let { patchAgeMonths(it, now) }
        checks += Check(
            "patch", "Security patch recent",
            when {
                age == null -> Check.Status.FAIL
                age > maxPatchAge -> Check.Status.FAIL
                age > 6 -> Check.Status.WARN
                else -> Check.Status.PASS
            },
            patch?.let { "${formatPatch(it)} (${age ?: "?"} months old)" } ?: "unknown",
        )

        if (hw.attestedIds.isEmpty()) {
            checks += Check("device_ids", "Hardware-attested model", Check.Status.INFO, "this phone does not attest its model")
        } else {
            val mismatched = hw.attestedIds.filter { (k, v) -> reported[k].orEmpty().trim() != v.trim() }.keys
            checks += Check(
                "device_ids", "Reported model matches hardware",
                if (mismatched.isEmpty()) Check.Status.PASS else Check.Status.FAIL,
                if (mismatched.isEmpty()) "${hw.attestedIds["manufacturer"].orEmpty()} ${hw.attestedIds["model"].orEmpty()}".trim()
                else "spoofed: ${mismatched.joinToString()}",
            )
        }
    }

    companion object {
        const val GOOGLE_STATUS_URL = "https://android.googleapis.com/attestation/status"

        fun rootKeysFromJson(json: String): List<ByteArray> {
            val cf = CertificateFactory.getInstance("X.509")
            val arr = JSONArray(json)
            return (0 until arr.length()).map {
                (cf.generateCertificate(ByteArrayInputStream(arr.getString(it).toByteArray())) as X509Certificate).publicKey.encoded
            }
        }

        /** Parses Google's status list into lowercase hex serials. */
        fun parseRevocations(json: String): Set<String> =
            JSONObject(json).getJSONObject("entries").keys().asSequence()
                .map { it.lowercase().trimStart('0').ifEmpty { "0" } }.toSet()

        fun fetchRevocations(timeoutMs: Int = 8000): Set<String>? = runCatching {
            val conn = URL(GOOGLE_STATUS_URL).openConnection() as HttpURLConnection
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            try {
                parseRevocations(conn.inputStream.use { it.readBytes().toString(Charsets.UTF_8) })
            } finally {
                conn.disconnect()
            }
        }.getOrNull()

        /** X509Certificate.getExtensionValue returns the DER OCTET STRING wrapper; unwrap it. */
        fun unwrapOctetString(der: ByteArray): ByteArray = Der.readSingle(der).asBytes()

        fun patchAgeMonths(level: Int, now: Date): Int? {
            val ym = if (level > 999_999) level / 100 else level
            val year = ym / 100
            val month = ym % 100
            if (month !in 1..12 || year < 2000) return null
            val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC")).apply { time = now }
            return (cal.get(Calendar.YEAR) - year) * 12 + (cal.get(Calendar.MONTH) + 1 - month)
        }

        fun formatPatch(level: Int): String {
            val ym = if (level > 999_999) level / 100 else level
            return "%04d-%02d".format(ym / 100, ym % 100)
        }

        private fun shortName(c: X509Certificate): String =
            c.subjectX500Principal.name.split(',').firstOrNull { it.startsWith("CN=") }?.removePrefix("CN=")
                ?: c.subjectX500Principal.name.take(48)

        private fun SecurityLevel.label() = when (this) {
            SecurityLevel.SOFTWARE -> "software only (emulator or broken keystore)"
            SecurityLevel.TRUSTED_ENVIRONMENT -> "Trusted Execution Environment"
            SecurityLevel.STRONG_BOX -> "StrongBox"
        }
    }
}
