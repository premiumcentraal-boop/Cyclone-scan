package com.devicetrust.scanner

import com.devicetrust.client.Decision
import com.devicetrust.client.DeviceInfo
import com.devicetrust.client.EvidenceStatus
import com.devicetrust.client.ScanEvidenceStatus
import com.devicetrust.client.ScanPolicy
import com.devicetrust.client.ServerScan
import com.devicetrust.client.UnavailableReason
import com.devicetrust.scanner.attest.AttestationReport
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.scan.DebugReport
import com.devicetrust.scanner.scan.LabRecord
import com.devicetrust.scanner.scan.ScanResult
import com.devicetrust.scanner.scan.ScanTrace
import com.devicetrust.scanner.scan.Verdict
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.IOException
import java.util.Date

/** Run 31: the report file says what could not be scanned, why, and how to look into it. */
class DebugReportTest {
    private val now = 1_760_000_200_000L
    private val app = DebugReport.AppInfo("com.devicetrust.scanner", "0.9.0-dev.1", 6, "ab".repeat(32), false,
        "com.android.packageinstaller")
    private val device = DebugReport.DeviceEnv("Google", "google", "Pixel 8", "shiba", "shiba", 35, "15",
        "2026-09-05", listOf("arm64-v8a"), true)

    private fun trace(): ScanTrace {
        var t = 0L
        val trace = ScanTrace { t.also { t += 5 } }
        trace.phase("load_attestation_roots") { 1 }
        trace.record("revocation_list", ScanTrace.Outcome.FAILED, 8000, "revocation not established",
            IOException("Unable to resolve host android.googleapis.com", java.net.UnknownHostException("https://android.googleapis.com/x")))
        trace.optional("hardware_key_generation") { throw IllegalStateException("keystore failed at /data/misc/keystore/user_0") }
        trace.record("native_collector", ScanTrace.Outcome.DEGRADED, 0, "native library not loaded: UnsatisfiedLinkError")
        return trace
    }

    private val signals = JSONObject().put("v", 1)
        .put("root_su", false).put("root_su_status", "NOT_DETECTED").put("root_su_reason", "COMPLETED")
        .put("root_magisk", false).put("root_magisk_status", "UNAVAILABLE").put("root_magisk_reason", "ACCESS_DENIED")
        .put("env_vpn", false).put("env_vpn_status", "UNSUPPORTED").put("env_vpn_reason", "API_UNSUPPORTED")
        .put("native_root_su_status", "UNSUPPORTED")

    private fun local() = ScanResult(
        verdict = Verdict.BLOCK, score = 100, factors = emptyList(),
        attestation = AttestationReport(
            listOf(Check("keygen", "Hardware key attestation available", Check.Status.FAIL, "could not create"),
                Check("revocation", "Not revoked", Check.Status.UNVERIFIED, "revocation list unavailable")),
            null, 0, null, false,
        ),
        signals = signals, device = DeviceInfo("google", "shiba", "shiba", "Google", "Pixel 8"),
        strongBoxKey = false, signingDigest = null, durationMs = 9000, scannedAt = Date(now - 1000), trace = trace(),
    )

    private fun inputs(
        local: ScanResult? = local(),
        failure: DebugReport.ScanFailure? = null,
        server: ServerScan? = null,
    ) = DebugReport.Inputs(
        app = app, device = device, local = local, localFailure = failure,
        server = server?.let { LabRecord.ServerRun(it, 1200, now) },
        serverSteps = listOf(DebugReport.ServerStepInfo("Enrollment", "ALLOW", listOf("ENROLLMENT_LEGACY_UNBOUND"))),
        biometric = listOf(Check("bio_hw", "Strong biometric hardware", Check.Status.UNVERIFIED, "no fingerprint enrolled")),
        nowMillis = now,
    )

    private fun items(report: JSONObject): List<JSONObject> =
        report.getJSONArray("notScanned").let { a -> (0 until a.length()).map { a.getJSONObject(it) } }

    @Test
    fun everythingThatCouldNotBeScannedIsListedWithReasonAndHint() {
        val report = DebugReport.build(inputs())
        val byId = items(report).associateBy { it.getString("kind") + ":" + it.getString("id") }
        val magisk = byId.getValue("check:root_magisk")
        assertEquals("UNAVAILABLE", magisk.getString("state"))
        assertEquals("ACCESS_DENIED", magisk.getString("reason"))
        assertTrue(magisk.getString("explanation").contains("did not allow"))
        assertTrue(magisk.getString("developerHint").contains("sandboxing"))
        assertEquals("UNSUPPORTED", byId.getValue("check:env_vpn").getString("state"))
        assertTrue(byId.getValue("check:native_root_su").getString("developerHint").contains("native_collector"))
        // Checks the collector never reported are not silently dropped.
        assertEquals("UNREPORTED", byId.getValue("check:hook_frida").getString("state"))
        assertEquals("UNVERIFIED", byId.getValue("attestation_check:revocation").getString("state"))
        assertEquals("NOT_EVALUATED", byId.getValue("layer:play_integrity").getString("state"))
        assertEquals("FAILED", byId.getValue("phase:revocation_list").getString("state"))
        assertEquals("FAILED", byId.getValue("phase:hardware_key_generation").getString("state"))
        assertEquals("DEGRADED", byId.getValue("phase:native_collector").getString("state"))
        assertEquals("UNVERIFIED", byId.getValue("biometric:bio_hw").getString("state"))
        assertFalse(byId.containsKey("check:root_su"))  // completed checks are results, not gaps
        val summary = report.getJSONObject("summary")
        assertEquals("COMPLETED", summary.getString("localScan"))
        assertEquals(items(report).size, summary.getInt("notScannedItems"))
        assertEquals(summary.getInt("checksTotal") - summary.getInt("checksCompleted"), summary.getInt("checksNotScanned"))
    }

    @Test
    fun errorsAreKeptButSanitized() {
        val report = DebugReport.build(inputs())
        val errors = report.getJSONArray("errors")
        val text = errors.toString()
        assertTrue(text.contains("java.io.IOException"))
        assertTrue(text.contains("java.lang.IllegalStateException"))
        assertFalse(text.contains("/data/misc"))          // file paths removed
        assertFalse(text.contains("https://"))            // URLs removed
        assertTrue(text.contains("<path>") && text.contains("<url>"))
        val phases = report.getJSONArray("phases")
        assertEquals(4, phases.length())
        assertEquals("load_attestation_roots", phases.getJSONObject(0).getString("phase"))
    }

    @Test
    fun aScanThatCrashedStillProducesAReport() {
        val partial = ScanTrace().apply {
            phase("load_attestation_roots") { 1 }
            runCatching { phase("attestation_verification") { throw RuntimeException("boom") } }
        }
        val report = DebugReport.build(inputs(local = null, failure = DebugReport.ScanFailure(
            "java.lang.RuntimeException", "boom", partial)))
        assertEquals("FAILED", report.getJSONObject("summary").getString("localScan"))
        assertTrue(report.isNull("localScan"))
        val ids = items(report).map { it.getString("id") }
        assertTrue("local_scan" in ids && "attestation_verification" in ids)
        assertEquals(2, report.getJSONArray("phases").length())
    }

    @Test
    fun serverGapsAreIncluded() {
        val unavailable = DebugReport.build(inputs(server = ServerScan.Unavailable(UnavailableReason.NETWORK, "trust API unreachable")))
        assertTrue(items(unavailable).any { it.getString("id") == "server_verified_scan" && it.getString("reason") == "NETWORK" })
        val partial = ServerScan.Verified(Decision.ALLOW, "dec_1", now, now + 300_000, ScanPolicy("beta", "abcd", "r"),
            ScanEvidenceStatus(EvidenceStatus.VERIFIED, EvidenceStatus.VERIFIED, EvidenceStatus.NOT_PROVIDED, EvidenceStatus.SIGNED),
            null, null)
        val report = DebugReport.build(inputs(server = partial))
        val play = items(report).single { it.getString("kind") == "server_evidence" }
        assertEquals("playIntegrity", play.getString("id"))
        assertEquals("ALLOW", report.getJSONObject("server").getJSONObject("lastVerifiedScan").getString("decision"))
        assertEquals("ENROLLMENT_LEGACY_UNBOUND",
            report.getJSONObject("server").getJSONArray("steps").getJSONObject(0).getJSONArray("reasons").getString(0))
    }

    @Test
    fun containsFullContextAndNoIdentifiers() {
        val export = DebugReport.export(inputs())
        val report = JSONObject(export.json)
        assertEquals(DebugReport.SCHEMA, report.getString("schema"))
        assertEquals("0.9.0-dev.1", report.getJSONObject("app").getString("versionName"))
        assertEquals("arm64-v8a", report.getJSONObject("device").getJSONArray("supportedAbis").getString(0))
        assertNotNull(report.getJSONObject("localScan").getJSONArray("findings"))
        val lower = export.json.lowercase()
        // No identifier fields anywhere (the privacy notices may mention the words).
        for (key in listOf("imei", "serial", "meid", "password", "token", "account", "serverurl")) {
            assertFalse("report has a \"$key\" field", Regex("\"$key\"\\s*:").containsMatchIn(lower))
        }
        assertEquals("cyclone-scan-report-google-pixel-8-20251009-085640Z.json", export.fileName)
        // A sample for CI's Python check (tools/check_debug_report.py).
        File("build").apply { mkdirs() }.resolve("debug-report-sample.json").writeText(export.json)
    }

    @Test
    fun sanitizeKeepsOrdinaryText() {
        assertEquals("3/4 checks done", ScanTrace.sanitize("3/4 checks   done"))
        assertEquals("open <path> failed", ScanTrace.sanitize("open /proc/self/maps failed"))
        assertTrue(ScanTrace.sanitize("x".repeat(1000)).length <= ScanTrace.MAX_MESSAGE)
    }
}
