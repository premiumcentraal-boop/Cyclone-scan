package com.devicetrust.scanner.scan

import com.devicetrust.client.EvidenceStatus
import com.devicetrust.client.ServerScan
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.risk.LocalRisk
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Run 31: the downloadable results/debug file for developers.
 *
 * One JSON document with the full context of everything this app ran on the phone:
 * - `summary`: verdict and how much of the scan completed
 * - `notScanned`: every check, layer, comparison, phase or server step that could **not**
 *   be scanned, with its state, the reason, a plain explanation and a developer hint
 * - `errors` and `phases`: what failed, how long each step took, sanitized exceptions
 * - `app` / `device`: build and environment needed to reproduce it
 * - `localScan`: the complete schema-2 scan report; `server` / `biometric` when they ran
 *
 * Contains no serial, IMEI, account data, server address, tokens or file paths (error
 * messages are sanitized by [ScanTrace.sanitize]). Pure Kotlin so it is unit-tested.
 */
object DebugReport {
    const val SCHEMA = "cyclone-scan-debug-report"
    const val SCHEMA_VERSION = 1

    data class AppInfo(
        val packageName: String,
        val versionName: String,
        val versionCode: Long,
        val apkSha256: String?,
        val debuggable: Boolean,
        val installer: String?,
    )

    data class DeviceEnv(
        val manufacturer: String,
        val brand: String,
        val model: String,
        val device: String,
        val product: String,
        val sdkInt: Int,
        val release: String,
        val securityPatch: String?,
        val supportedAbis: List<String>,
        val strongBoxFeature: Boolean?,
    )

    /** The local scan threw before producing a result. */
    data class ScanFailure(val errorType: String?, val errorMessage: String?, val trace: ScanTrace?)

    data class ServerStepInfo(val title: String, val decision: String, val reasons: List<String>)

    data class Inputs(
        val app: AppInfo,
        val device: DeviceEnv,
        val local: ScanResult? = null,
        val localFailure: ScanFailure? = null,
        val server: LabRecord.ServerRun? = null,
        val serverSteps: List<ServerStepInfo> = emptyList(),
        val serverError: String? = null,
        val biometric: List<Check> = emptyList(),
        val nowMillis: Long,
    )

    data class Export(val fileName: String, val json: String)

    fun export(inputs: Inputs): Export = Export(fileName(inputs.device, inputs.nowMillis), build(inputs).toString(2))

    fun fileName(device: DeviceEnv, nowMillis: Long): String {
        val model = "${device.manufacturer}-${device.model}".lowercase(Locale.ROOT)
            .replace(Regex("[^a-z0-9]+"), "-").trim('-').take(40).ifEmpty { "device" }
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(nowMillis))
        return "cyclone-scan-report-$model-${stamp}Z.json"
    }

    fun build(i: Inputs): JSONObject {
        val notScanned = notScanned(i)
        val phases = i.local?.trace ?: i.localFailure?.trace
        return JSONObject().apply {
            put("schema", SCHEMA)
            put("schemaVersion", SCHEMA_VERSION)
            put("generatedAt", LabRecord.iso(i.nowMillis))
            put("purpose", "Results and debug export for developers: what was scanned, what was not, and why.")
            put("app", JSONObject()
                .put("packageName", i.app.packageName)
                .put("versionName", i.app.versionName.take(32))
                .put("versionCode", i.app.versionCode)
                .put("apkSha256", i.app.apkSha256 ?: JSONObject.NULL)
                .put("debuggable", i.app.debuggable)
                .put("installer", i.app.installer ?: JSONObject.NULL))
            put("device", JSONObject()
                .put("manufacturer", i.device.manufacturer).put("brand", i.device.brand).put("model", i.device.model)
                .put("device", i.device.device).put("product", i.device.product)
                .put("sdkInt", i.device.sdkInt).put("release", i.device.release)
                .put("securityPatch", i.device.securityPatch ?: JSONObject.NULL)
                .put("supportedAbis", JSONArray(i.device.supportedAbis))
                .put("strongBoxFeature", i.device.strongBoxFeature ?: JSONObject.NULL))
            put("summary", summary(i, notScanned))
            put("notScanned", JSONArray(notScanned))
            put("errors", JSONArray(errors(i)))
            put("phases", phases?.toJson() ?: JSONArray())
            put("localScan", i.local?.toJson() ?: JSONObject.NULL)
            put("server", server(i))
            put("biometric", if (i.biometric.isEmpty()) JSONObject.NULL else JSONArray(i.biometric.map { checkJson(it) }))
            put("privacy", "No serial number, IMEI, account data, server address, tokens or file paths. Error " +
                "messages are sanitized. Includes the device model, OS/patch facts, the app's own signer digest " +
                "and check states.")
        }
    }

    private fun summary(i: Inputs, notScanned: List<JSONObject>): JSONObject {
        val out = JSONObject()
        val local = i.local
        if (local == null) {
            out.put("localScan", if (i.localFailure != null) "FAILED" else "NOT_RUN")
        } else {
            val findings = local.findings
            out.put("localScan", "COMPLETED")
            out.put("verdict", local.verdict.name)
            out.put("score", local.score)
            out.put("checksTotal", findings.size)
            out.put("checksCompleted", findings.count { it.state.completed })
            out.put("checksDetected", findings.count { it.state == ReportState.DETECTED })
            out.put("checksNotScanned", findings.count { !it.state.completed })
            out.put("hardFailures", JSONArray(local.hardFailures.map { it.id }))
            out.put("durationMs", local.durationMs)
        }
        out.put("serverScan", when (val s = i.server?.scan) {
            null -> "NOT_RUN"
            is ServerScan.Unavailable -> "UNAVAILABLE"
            is ServerScan.Verified -> s.label(i.nowMillis).name
        })
        out.put("biometricTest", if (i.biometric.isEmpty()) "NOT_RUN" else "RAN")
        out.put("notScannedItems", notScanned.size)
        return out
    }

    private fun item(kind: String, id: String, label: String, state: String, reason: String?, explanation: String,
                     hint: String, extra: JSONObject.() -> Unit = {}) = JSONObject().apply {
        put("kind", kind)
        put("id", id)
        put("label", label)
        put("state", state)
        put("reason", reason ?: JSONObject.NULL)
        put("explanation", explanation)
        put("developerHint", hint)
        extra()
    }

    /** Everything that could not be scanned or verified, across all sources. */
    fun notScanned(i: Inputs): List<JSONObject> {
        val out = mutableListOf<JSONObject>()
        i.localFailure?.let { f ->
            out += item("scan", "local_scan", "Local scan", "FAILED", f.errorType,
                "the local scan stopped before it produced a result" + (f.errorMessage?.let { ": $it" } ?: ""),
                "See errors and phases: the last phase before the failure is where the scan stopped.")
        }
        i.local?.let { local ->
            for (f in local.findings.filter { !it.state.completed }) {
                out += item("check", f.id, LocalRisk.DESCRIPTIONS[f.id] ?: f.id, f.state.name, f.reason,
                    explanation(f), checkHint(f)) { put("source", f.source.name) }
            }
            for (c in local.attestation.checks.filter { it.status == Check.Status.UNVERIFIED }) {
                out += item("attestation_check", c.id, c.label, "UNVERIFIED", null, c.detail.take(160),
                    "The attestation chain did not carry this field, or it could not be checked on-device.")
            }
            for (c in ReportCoverage.comparisons(local.evidence, local.signals).filter { !it.comparable }) {
                out += item("comparison", c.factor, LocalRisk.DESCRIPTIONS[c.factor] ?: c.factor, "NOT_COMPARED", null,
                    c.missing, "One side of this hardware-versus-reported comparison was missing; see explanation.")
            }
            for (l in local.layers.filter { it.state in NOT_DONE_LAYERS }) {
                out += item("layer", l.id, l.label, l.state.name, null, l.detail, layerHint(l.state)) {
                    put("source", l.source.name)
                }
            }
        }
        val phases = i.local?.trace ?: i.localFailure?.trace
        phases?.all?.filter { it.outcome != ScanTrace.Outcome.OK }?.forEach { p ->
            out += item("phase", p.id, PHASE_LABELS[p.id] ?: p.id, p.outcome.name, p.errorType,
                p.errorMessage ?: p.detail ?: "no further detail", phaseHint(p.id))
        }
        when (val s = i.server?.scan) {
            is ServerScan.Unavailable -> out += item("server", "server_verified_scan", "Server-verified scan",
                "UNAVAILABLE", s.reason.name, s.detail?.let { ScanTrace.sanitize(it) } ?: "no server verdict",
                "Check the server URL, that it listens on the network, and its logs for this time.")
            is ServerScan.Verified -> {
                val e = s.evidence
                listOf("deviceKeySignature" to e.deviceKeySignature, "freshAttestation" to e.freshAttestation,
                    "playIntegrity" to e.playIntegrity, "clientSignals" to e.clientSignals)
                    .filter { it.second !in setOf(EvidenceStatus.VERIFIED, EvidenceStatus.SIGNED) }
                    .forEach { (id, status) ->
                        out += item("server_evidence", id, "Server evidence: $id", status.name, null,
                            "the server did not verify this evidence for the last scan",
                            if (id == "playIntegrity") "Play Integrity needs a Cloud project number and a Play-recognized build."
                            else "Run the server with --expose-reasons and compare the reasons in server.")
                    }
            }
            null -> Unit
        }
        i.serverError?.let {
            out += item("server", "server_flow", "Server test", "FAILED", null, ScanTrace.sanitize(it),
                "The server flow stopped with this error; see the server's decision log.")
        }
        for (c in i.biometric.filter { it.status == Check.Status.UNVERIFIED }) {
            out += item("biometric", c.id, c.label, "UNVERIFIED", null, c.detail.take(160),
                "Biometric hardware or enrollment may be missing on this phone.")
        }
        return out
    }

    private fun errors(i: Inputs): List<JSONObject> {
        val out = mutableListOf<JSONObject>()
        i.localFailure?.let {
            out += JSONObject().put("where", "local_scan").put("type", it.errorType ?: JSONObject.NULL)
                .put("message", it.errorMessage ?: JSONObject.NULL)
        }
        (i.local?.trace ?: i.localFailure?.trace)?.all?.filter { it.errorType != null || it.outcome == ScanTrace.Outcome.FAILED }
            ?.forEach { p ->
                out += JSONObject().put("where", p.id).put("type", p.errorType ?: JSONObject.NULL)
                    .put("message", p.errorMessage ?: p.detail ?: JSONObject.NULL)
            }
        i.serverError?.let {
            out += JSONObject().put("where", "server_flow").put("type", JSONObject.NULL).put("message", ScanTrace.sanitize(it))
        }
        return out
    }

    private fun server(i: Inputs): Any {
        if (i.server == null && i.serverSteps.isEmpty() && i.serverError == null) return JSONObject.NULL
        return JSONObject().apply {
            put("lastVerifiedScan", i.server?.let { LabRecord.serverJson(it, i.nowMillis) } ?: JSONObject.NULL)
            put("steps", JSONArray(i.serverSteps.map { s ->
                JSONObject().put("title", s.title.take(64)).put("decision", s.decision.take(32))
                    .put("reasons", JSONArray(s.reasons.take(32)))
            }))
            put("error", i.serverError?.let { ScanTrace.sanitize(it) } ?: JSONObject.NULL)
        }
    }

    private fun checkJson(c: Check) = JSONObject().put("id", c.id).put("label", c.label).put("status", c.status.name)
        .put("detail", c.detail.take(160))

    private val NOT_DONE_LAYERS = setOf(LayerState.UNAVAILABLE, LayerState.PARTIAL, LayerState.NOT_EVALUATED)

    val PHASE_LABELS = mapOf(
        "load_attestation_roots" to "Load Google attestation roots",
        "revocation_list" to "Download Google revocation list",
        "hardware_key_generation" to "Create an attested hardware key",
        "attestation_verification" to "Verify the attestation chain",
        "device_signals" to "Run on-phone checks",
        "native_collector" to "Run native checks",
        "risk_scoring" to "Score the findings",
    )

    private fun explanation(f: Finding): String = when (f.state) {
        ReportState.UNAVAILABLE -> "could not verify: " + ReportCoverage.reasonText(f.reason)
        ReportState.UNSUPPORTED -> "not supported on this device or Android version"
        ReportState.UNREPORTED -> "the collector did not report a result for this check"
        else -> f.state.name
    }

    fun checkHint(f: Finding): String = when (f.source) {
        EvidenceSource.LOCAL_NATIVE -> when (f.state) {
            ReportState.UNSUPPORTED -> "Native library not loaded for this ABI, or the check is unsupported here; see the native_collector phase."
            ReportState.UNAVAILABLE -> "The native check could not read its source inside this process."
            else -> "The native collector returned no result; see the native_collector phase."
        }
        else -> when (f.state) {
            ReportState.UNREPORTED -> "The collector emitted no ${f.id}_status: scanner and SDK versions disagree, or the check threw before reporting."
            ReportState.UNSUPPORTED -> "Not available at this API level; add a fallback source or keep it UNSUPPORTED."
            else -> when (f.reason) {
                "ACCESS_DENIED" -> "Blocked by Android app sandboxing (normal on newer Android); look for an API-based source or accept UNAVAILABLE."
                "PARTIAL_COVERAGE" -> "Only some of this check's sources were readable; review which sources fail on this OS version."
                "READ_ERROR" -> "An I/O error occurred while reading; review the probe's error handling and timeouts."
                "MALFORMED" -> "The source had an unexpected format; capture it on this OS version and extend the parser."
                "TOO_LARGE" -> "The source exceeded the bounded read limit; review the limit for this source."
                "API_ERROR" -> "The Android API threw; check permissions and OEM behaviour on this model."
                "API_UNSUPPORTED" -> "This Android version lacks the API; add a fallback or mark UNSUPPORTED."
                else -> "The collector gave no reason code; add one in DeviceSignals for this check."
            }
        }
    }

    private fun layerHint(state: LayerState): String = when (state) {
        LayerState.NOT_EVALUATED -> "Needs the verification server; run the Server tab against a server to cover it."
        LayerState.PARTIAL -> "Some checks in this layer did not complete; see the check items above."
        else -> "This layer could not run; see phases and errors."
    }

    private fun phaseHint(id: String): String = when (id) {
        "revocation_list" -> "The phone could not download https://android.googleapis.com/attestation/status (offline, proxy or DNS)."
        "hardware_key_generation" -> "KeyStore could not create an attested key: no TEE/StrongBox attestation, or a vendor KeyMint error."
        "native_collector" -> "Check that libdtnative.so is packaged for this ABI and loads (see errorMessage)."
        "load_attestation_roots" -> "The bundled google_roots.json asset is missing or unreadable."
        else -> "See errorType and errorMessage."
    }
}
