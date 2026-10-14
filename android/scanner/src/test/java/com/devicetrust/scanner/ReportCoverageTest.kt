package com.devicetrust.scanner

import com.devicetrust.client.DeviceInfo
import com.devicetrust.client.signals.NativeSignals
import com.devicetrust.scanner.attest.AttestationReport
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.risk.LocalRisk
import com.devicetrust.scanner.scan.EvidenceSource
import com.devicetrust.scanner.scan.LayerState
import com.devicetrust.scanner.scan.ReportCoverage
import com.devicetrust.scanner.scan.ReportState
import com.devicetrust.scanner.scan.ScanResult
import com.devicetrust.scanner.scan.Verdict
import com.devicetrust.scanner.ui.signalGroups
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/** Run 14: the scanner never shows an incomplete check as a clean pass, and local mode never implies server checks. */
class ReportCoverageTest {
    private val bools = ReportCoverage.LOCAL_CHECKS - setOf("env_a11y_third_party", "env_remote_access_apps")
    private val values = listOf("app_installer", "app_signature_sha256", "os_security_patch", "os_release")

    private fun signals(state: String, reason: String): JSONObject = JSONObject().apply {
        put("v", 1)
        put("signal_coverage_version", 1)
        bools.forEach { put(it, state == "DETECTED") }
        put("env_a11y_third_party", 0)
        put("env_remote_access_apps", JSONArray())
        ReportCoverage.LOCAL_CHECKS.forEach { put(it + "_status", state); put(it + "_reason", reason) }
        put("app_installer", "com.android.vending")
        put("app_signature_sha256", "ab".repeat(32))
        put("os_security_patch", "2026-09-05")
        put("os_release", "16")
        values.forEach { put(it + "_status", "COLLECTED"); put(it + "_reason", "COMPLETED") }
        NativeSignals.CHECKS.forEach { put("native_$it", false); put("native_${it}_status", "UNAVAILABLE") }
    }

    private val evidence = LocalRisk.Evidence(
        osPatchLevel = 202609, securityLevel = "TRUSTED_ENVIRONMENT", chainType = "RKP",
        osVersion = 160000, vendorPatchLevel = 20260905, bootPatchLevel = 20260905,
    )

    private fun rows(s: JSONObject, ev: LocalRisk.Evidence? = evidence, signer: Boolean = true) =
        signalGroups(s, LocalRisk.assess(s, ev, setOf("ab".repeat(32))).factors, ev, signer)
            .flatMap { g -> g.rows.map { g.title to it } }

    @Test
    fun deniedChecksAreNeverShownAsPassing() {
        val s = signals("UNAVAILABLE", "ACCESS_DENIED")
        val local = rows(s).filter { (group, _) ->
            group in setOf("Root", "Hooking & debugging", "Emulator", "Scam & remote control", "Device settings")
        }
        assertEquals(ReportCoverage.LOCAL_CHECKS.size, local.size)
        local.forEach { (_, row) ->
            assertEquals(row.label, Check.Status.UNVERIFIED, row.status)
            assertTrue(row.detail, row.detail.contains("not evidence of safety"))
        }
        // Score is unchanged by coverage: nothing detected, nothing added.
        assertEquals(LocalRisk.assess(signals("NOT_DETECTED", "COMPLETED"), evidence, setOf("ab".repeat(32))),
            LocalRisk.assess(s, evidence, setOf("ab".repeat(32))))
    }

    @Test
    fun completedCleanChecksPass() {
        rows(signals("NOT_DETECTED", "COMPLETED"))
            .filter { (group, _) -> group != "Native versus Kotlin" }
            .forEach { (_, row) -> assertEquals(row.label, Check.Status.PASS, row.status) }
    }

    @Test
    fun legacyReportWithoutStatesIsUnreported() {
        val legacy = JSONObject().put("v", 1).put("root_su", false).put("hook_frida", true)
        assertEquals(ReportState.UNREPORTED, ReportCoverage.localState(legacy, "root_su"))
        assertEquals(ReportState.DETECTED, ReportCoverage.localState(legacy, "hook_frida"))
    }

    @Test
    fun comparisonsWithoutAttestationAreNotCompared() {
        val all = rows(signals("NOT_DETECTED", "COMPLETED"), ev = null, signer = false)
        val keybox = all.filter { it.first == "Keybox & spoofing" }
        assertEquals(4, keybox.size)
        keybox.forEach { (_, row) -> assertEquals(row.label, Check.Status.UNVERIFIED, row.status) }
        val signature = all.first { it.second.label.startsWith("App signature") }.second
        assertEquals(Check.Status.UNVERIFIED, signature.status)
    }

    @Test
    fun codenameReleaseIsNotCompared() {
        val s = signals("NOT_DETECTED", "COMPLETED").put("os_release", "Baklava")
        val row = rows(s).first { it.second.label.startsWith("Reported Android version") }.second
        assertEquals(Check.Status.UNVERIFIED, row.status)
    }

    @Test
    fun installerStatesAreDistinguished() {
        val failed = signals("NOT_DETECTED", "COMPLETED").put("app_installer", JSONObject.NULL)
            .put("app_installer_status", "UNAVAILABLE").put("app_installer_reason", "API_ERROR")
        assertEquals(Check.Status.UNVERIFIED, rows(failed).first { it.second.label == "Installed from Google Play" }.second.status)
        val sideloaded = signals("NOT_DETECTED", "COMPLETED").put("app_installer", JSONObject.NULL)
        val row = rows(sideloaded).first { it.second.label == "Installed from Google Play" }.second
        assertEquals(Check.Status.WARN, row.status)
    }

    @Test
    fun localModeNeverClaimsServerChecks() {
        val report = AttestationReport(emptyList(), null, 3, "Google", true, "RKP")
        val layers = ReportCoverage.layers(report, ReportCoverage.findings(signals("NOT_DETECTED", "COMPLETED")))
            .associateBy { it.id }
        listOf("play_integrity", "server_policy", "fleet_history", "official_signer").forEach {
            assertEquals(it, LayerState.NOT_EVALUATED, layers.getValue(it).state)
            assertEquals(it, EvidenceSource.SERVER, layers.getValue(it).source)
        }
        assertEquals(LayerState.COMPLETE, layers.getValue("local_checks").state)
        assertEquals(LayerState.UNAVAILABLE, layers.getValue("native_checks").state)

        val noKey = AttestationReport(listOf(Check("keygen", "k", Check.Status.FAIL)), null, 0, null, false)
        val l2 = ReportCoverage.layers(noKey, ReportCoverage.findings(signals("UNAVAILABLE", "ACCESS_DENIED")))
            .associateBy { it.id }
        assertEquals(LayerState.UNAVAILABLE, l2.getValue("hardware_attestation").state)
        assertEquals(LayerState.UNAVAILABLE, l2.getValue("revocation_list").state)
        assertEquals(LayerState.UNAVAILABLE, l2.getValue("local_checks").state)
    }

    @Test
    fun exportIsVersionedTypedAndBounded() {
        val s = signals("UNAVAILABLE", "PARTIAL_COVERAGE")
        val result = ScanResult(
            verdict = Verdict.BLOCK, score = 100, factors = emptyList(),
            attestation = AttestationReport(
                listOf(Check("ext_parse", "Attestation data well-formed", Check.Status.FAIL, "x".repeat(500))),
                null, 3, null, false,
            ),
            signals = s, device = DeviceInfo("google", "shiba", "shiba", "Google", "Pixel 8"),
            strongBoxKey = false, signingDigest = null, durationMs = 5, scannedAt = Date(0),
        )
        val json = result.toJson()
        assertEquals(ReportCoverage.SCHEMA, json.getString("reportSchema"))
        assertEquals(2, json.getInt("reportSchemaVersion"))
        // Earlier fields are kept for existing readers.
        listOf("scanner", "evaluationMode", "playIntegrityEvaluated", "fleetEvaluated", "officialSignerVerified",
            "verdict", "score", "factors", "device", "attestation", "signals").forEach { assertTrue(it, json.has(it)) }
        assertFalse(json.getBoolean("playIntegrityEvaluated"))
        val local = json.getJSONObject("coverage").getJSONObject("local")
        assertEquals(ReportCoverage.LOCAL_CHECKS.size, local.getInt("unavailable"))
        assertEquals(0, local.getInt("notDetected"))
        val findings = json.getJSONArray("findings")
        assertEquals(ReportCoverage.LOCAL_CHECKS.size + NativeSignals.CHECKS.size, findings.length())
        assertEquals("PARTIAL_COVERAGE", findings.getJSONObject(0).getString("reason"))
        val detail = json.getJSONObject("attestation").getJSONArray("checks").getJSONObject(0).getString("detail")
        assertEquals(ScanResult.MAX_DETAIL, detail.length)
        val text = json.toString()
        listOf("/proc/", "/data/", "/system/", "/sbin").forEach { assertFalse(it, text.contains(it)) }
    }
}
