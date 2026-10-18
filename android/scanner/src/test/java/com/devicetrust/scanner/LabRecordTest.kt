package com.devicetrust.scanner

import com.devicetrust.client.Decision
import com.devicetrust.client.DeviceInfo
import com.devicetrust.client.EvidenceStatus
import com.devicetrust.client.HistoryChange
import com.devicetrust.client.ScanEvidenceStatus
import com.devicetrust.client.ScanHistory
import com.devicetrust.client.ScanPolicy
import com.devicetrust.client.ServerDiagnostics
import com.devicetrust.client.ServerScan
import com.devicetrust.client.UnavailableReason
import com.devicetrust.scanner.attest.AttestationReport
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.scan.ApkDigest
import com.devicetrust.scanner.scan.LabRecord
import com.devicetrust.scanner.scan.ScanResult
import com.devicetrust.scanner.scan.Verdict
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Date

/** Run 30: the lab record carries measurements only, never operator declarations or identifiers. */
class LabRecordTest {
    private val apk = "ab".repeat(32)

    private val local = ScanResult(
        verdict = Verdict.ALLOW, score = 5, factors = listOf("env_vpn" to 5, "no_strongbox" to 0),
        attestation = AttestationReport(emptyList(), null, 3, "Google", true, "RKP"),
        signals = JSONObject().put("v", 1).put("env_vpn", true).put("env_vpn_status", "DETECTED"),
        device = DeviceInfo("google", "shiba", "shiba", "Google", "Pixel 8"),
        strongBoxKey = false, signingDigest = null, durationMs = 1800, scannedAt = Date(1_760_000_000_000L),
    )

    private val verified = ServerScan.Verified(
        Decision.ALLOW, "dec_1", 1_760_000_100_000L, 1_760_000_400_000L, ScanPolicy("beta", "abcd", "r"),
        ScanEvidenceStatus(EvidenceStatus.VERIFIED, EvidenceStatus.VERIFIED, EvidenceStatus.VERIFIED, EvidenceStatus.SIGNED),
        mapOf("NOT_DETECTED" to 21, "DETECTED" to 1),
        ScanHistory(2, 1.0, "enrollment", true, listOf(HistoryChange("FRESH_KEY_AUTHORIZED", "INFO", "leaf_spki_sha256"))),
        ServerDiagnostics(emptyList(), emptyList(), 5, listOf("env_vpn" to 5)),
        playRequested = true,
    )

    private fun record(server: ServerScan? = verified) = LabRecord.build(
        apkSha256 = apk, scannerVersion = "0.9.0-beta.1", os = "Android 16 (API 36)", local = local,
        server = server?.let { LabRecord.ServerRun(it, 2400, 1_760_000_100_000L) }, nowMillis = 1_760_000_200_000L,
    )

    @Test
    fun recordsMeasurementsOnly() {
        val r = record()
        assertEquals(LabRecord.SCHEMA, r.getString("schema"))
        assertEquals(1, r.getInt("schemaVersion"))
        assertEquals(apk, r.getString("apkSha256"))
        assertEquals(LabRecord.iso(1_760_000_200_000L), r.getString("recordedAt"))
        assertTrue(r.getString("recordedAt").endsWith("Z"))
        val l = r.getJSONObject("local")
        assertEquals("ALLOW", l.getString("verdict"))
        assertEquals(listOf("env_vpn"), (0 until l.getJSONArray("factors").length()).map { l.getJSONArray("factors").getString(it) })
        val s = r.getJSONObject("server")
        assertEquals("VERIFIED_FRESH", s.getString("label"))
        assertEquals(5, s.getInt("riskScore"))
        assertEquals("FRESH_KEY_AUTHORIZED", s.getJSONArray("historyChanges").getString(0))
        // No operator declarations, identifiers or addresses.
        val text = r.toString()
        for (forbidden in listOf("case_id", "ground_truth", "alias", "expectation", "serial", "imei", "http", "Pixel 8")) {
            assertFalse(forbidden, text.contains(forbidden, ignoreCase = true))
        }
    }

    @Test
    fun unavailableServerAndMissingScansAreExplicit() {
        val r = record(ServerScan.Unavailable(UnavailableReason.NETWORK))
        assertEquals("NETWORK", r.getJSONObject("server").getString("unavailable"))
        assertEquals("UNAVAILABLE", r.getJSONObject("server").getString("label"))
        val none = LabRecord.build(null, "x", "Android", null, null, 0)
        assertTrue(none.isNull("local") && none.isNull("server") && none.isNull("apkSha256"))
    }

    @Test
    fun apkDigestHashesTheFile() {
        val f = File.createTempFile("apk", ".bin").apply { writeBytes("abc".toByteArray()); deleteOnExit() }
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", ApkDigest.sha256(f))
    }

    /** Written for CI: tools.assurance.lab_import must accept what the app produces. */
    @Test
    fun writeSampleForImportCheck() {
        File("build").mkdirs()
        File("build/lab-record-sample.json").writeText(record().toString(2))
    }
}
