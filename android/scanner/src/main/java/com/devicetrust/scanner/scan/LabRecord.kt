package com.devicetrust.scanner.scan

import com.devicetrust.client.ServerScan
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Run 30: a "lab record" the operator shares from the phone after running a test case.
 *
 * It carries only what the app *measured*: the exact APK it is (SHA-256 of its own
 * installed file), the OS, the local diagnostic and the latest server-verified scan. It
 * deliberately has no place for the case, the phone's alias, the ground truth or whether
 * the expectation was met: the operator declares those on a computer with
 * `python -m tools.assurance.lab_import`, which turns this record into a lab observation
 * (`tools/assurance/lab.py`).
 *
 * No serial, IMEI, account data, server URL, tokens or free text are included.
 */
object LabRecord {
    const val SCHEMA = "cyclone-scan-lab-record"
    const val SCHEMA_VERSION = 1

    data class ServerRun(val scan: ServerScan, val durationMs: Long, val finishedAtMillis: Long)

    fun build(
        apkSha256: String?,
        scannerVersion: String,
        os: String,
        local: ScanResult?,
        server: ServerRun?,
        nowMillis: Long,
    ): JSONObject = JSONObject().apply {
        put("schema", SCHEMA)
        put("schemaVersion", SCHEMA_VERSION)
        put("recordedAt", iso(nowMillis))
        put("apkSha256", apkSha256 ?: JSONObject.NULL)
        put("scannerVersion", scannerVersion.take(32))
        put("os", os.take(96))
        put("local", local?.let(::localJson) ?: JSONObject.NULL)
        put("server", server?.let { serverJson(it, nowMillis) } ?: JSONObject.NULL)
    }

    private fun localJson(r: ScanResult): JSONObject {
        val findings = r.findings
        return JSONObject()
            .put("verdict", r.verdict.name)
            .put("score", r.score)
            .put("hardFailures", JSONArray(r.hardFailures.map { it.id }.take(32)))
            .put("factors", JSONArray(r.factors.filter { it.second > 0 }.map { it.first }.take(32)))
            .put("coverage", JSONObject()
                .put("local", ReportCoverage.counts(findings, EvidenceSource.LOCAL_CHECK).toJson())
                .put("native", ReportCoverage.counts(findings, EvidenceSource.LOCAL_NATIVE).toJson()))
            .put("durationMs", r.durationMs)
            .put("scannedAt", iso(r.scannedAt.time))
    }

    /** Also used by the Run 31 debug report. */
    fun serverJson(run: ServerRun, nowMillis: Long): JSONObject {
        val out = JSONObject()
            .put("durationMs", run.durationMs)
            .put("finishedAt", iso(run.finishedAtMillis))
            .put("label", run.scan.label(nowMillis).name)
        when (val s = run.scan) {
            is ServerScan.Unavailable -> out.put("unavailable", s.reason.name)
            is ServerScan.Verified -> {
                out.put("decision", s.decision.name)
                out.put("decisionId", s.decisionId.take(64))
                out.put("evidence", JSONObject()
                    .put("deviceKeySignature", s.evidence.deviceKeySignature.name)
                    .put("freshAttestation", s.evidence.freshAttestation.name)
                    .put("playIntegrity", s.evidence.playIntegrity.name)
                    .put("clientSignals", s.evidence.clientSignals.name))
                out.put("historyChanges", JSONArray(s.history?.changes.orEmpty().map { it.code }.distinct().take(32)))
                s.coverage?.let { counts -> out.put("coverage", JSONObject(counts)) }
                // Only a development server (--expose-reasons) returns these; the import tool
                // requires them, so a lab run uses such a server.
                s.diagnostics?.let { d ->
                    out.put("reasons", JSONArray(d.reasons.take(32)))
                    out.put("riskScore", d.riskScore ?: JSONObject.NULL)
                    out.put("riskFactors", JSONArray(d.riskFactors.filter { it.second > 0 }.map { it.first }.take(32)))
                }
            }
        }
        return out
    }

    fun iso(millis: Long): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.ROOT)
        .apply { timeZone = TimeZone.getTimeZone("UTC") }
        .format(Date(millis))
}
