package com.devicetrust.scanner.scan

import android.content.Context
import com.devicetrust.client.AndroidKeyAttester
import com.devicetrust.client.DeviceInfo
import com.devicetrust.scanner.attest.AttestationReport
import com.devicetrust.scanner.attest.ChainVerifier
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.attest.RevocationResolution
import com.devicetrust.scanner.attest.RevocationResolver
import com.devicetrust.scanner.attest.RevocationSource
import com.devicetrust.scanner.risk.LocalRisk
import com.devicetrust.client.signals.AndroidSignalProbe
import com.devicetrust.client.signals.DeviceSignals
import com.devicetrust.client.signals.JniNativeProbe
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Date
import java.util.UUID

enum class Verdict { ALLOW, STEP_UP, BLOCK }

/** The phase detail for the revocation list, saying plainly when the copy is not live. */
internal fun revocationDetail(r: RevocationResolution): String = when (r.source) {
    RevocationSource.LIVE -> "${r.serials?.size ?: 0} entries"
    RevocationSource.CACHED -> "live download failed; using the copy saved ${(r.cachedAgeMs ?: 0L) / 60_000} min ago"
    RevocationSource.NONE -> "revocation not established"
}

/** Result of one local scan. Contains no serial, IMEI or account data. */
class ScanResult(
    val verdict: Verdict,
    val score: Int,
    val factors: List<Pair<String, Int>>,
    val attestation: AttestationReport,
    val signals: JSONObject,
    val device: DeviceInfo,
    val strongBoxKey: Boolean,
    val signingDigest: String?,
    val durationMs: Long,
    val scannedAt: Date,
    /** Hardware-attested evidence used by the local risk engine; null without attestation. */
    val evidence: LocalRisk.Evidence? = null,
    /** True only when the attestation listed this app's signer, so the signature row compared something. */
    val attestedSignerAvailable: Boolean = false,
    /** Run 30: the installed app's versionName (the constant was not bumped by later runs). */
    val scannerVersion: String = SCANNER_VERSION,
    /** Run 31: phase timings, outcomes and sanitized errors of this scan (debug report). */
    val trace: ScanTrace = ScanTrace(),
) {
    val hardFailures: List<Check> get() = attestation.hardFailures
    val findings: List<Finding> get() = ReportCoverage.findings(signals)
    val layers: List<Layer> get() = ReportCoverage.layers(attestation, findings)

    /**
     * Shareable diagnostic report. Schema 2 (Run 14) is additive over the
     * 0.6.0 export: it keeps every earlier field and adds typed findings,
     * coverage counts and verification layers. It contains no serial, IMEI,
     * account data, file paths, memory maps or secrets; free-text details are
     * bounded.
     */
    fun toJson(): JSONObject = JSONObject().apply {
        put("reportSchema", ReportCoverage.SCHEMA)
        put("reportSchemaVersion", ReportCoverage.SCHEMA_VERSION)
        put("scanner", "device-trust-scanner/$scannerVersion")
        put("evaluationMode", "LOCAL_DIAGNOSTIC")
        put("playIntegrityEvaluated", false)
        put("fleetEvaluated", false)
        put("officialSignerVerified", false)
        put("scannedAt", scannedAt.time)
        put("verdict", verdict.name)
        put("score", score)
        put("factors", JSONArray(factors.map { JSONObject().put("factor", it.first).put("points", it.second) }))
        put("device", JSONObject().put("brand", device.brand).put("model", device.model)
            .put("manufacturer", device.manufacturer).put("device", device.device).put("product", device.product))
        put("attestation", JSONObject().apply {
            put("chainLength", attestation.chainLength)
            put("root", attestation.rootSubject)
            put("revocationChecked", attestation.revocationChecked)
            put("revocationSource", attestation.revocationSource)
            put("strongBoxKey", strongBoxKey)
            attestation.keyDescription?.let { kd ->
                put("attestationVersion", kd.attestationVersion)
                put("securityLevel", kd.attestationSecurityLevel.name)
                put("keyMintSecurityLevel", kd.keyMintSecurityLevel.name)
                put("osPatchLevel", kd.hardwareEnforced.osPatchLevel)
                put("vendorPatchLevel", kd.hardwareEnforced.vendorPatchLevel)
                put("bootState", kd.hardwareEnforced.rootOfTrust?.verifiedBootState?.name)
                put("chainType", attestation.chainType)
                put("osVersion", kd.hardwareEnforced.osVersion)
                put("bootPatchLevel", kd.hardwareEnforced.bootPatchLevel)
                put("deviceLocked", kd.hardwareEnforced.rootOfTrust?.deviceLocked)
                put("attestedIds", JSONObject(kd.hardwareEnforced.attestedIds as Map<*, *>))
            }
            put("checks", JSONArray(attestation.checks.map {
                JSONObject().put("id", it.id).put("status", it.status.name).put("detail", it.detail.take(MAX_DETAIL))
            }))
        })
        put("signals", signals)
        val all = findings
        put("coverage", JSONObject()
            .put("local", ReportCoverage.counts(all, EvidenceSource.LOCAL_CHECK).toJson())
            .put("native", ReportCoverage.counts(all, EvidenceSource.LOCAL_NATIVE).toJson()))
        put("findings", JSONArray(all.map { f ->
            JSONObject().put("id", f.id).put("source", f.source.name).put("state", f.state.name)
                .put("reason", f.reason ?: JSONObject.NULL)
        }))
        put("verification", JSONArray(ReportCoverage.layers(attestation, all).map { l ->
            JSONObject().put("id", l.id).put("source", l.source.name).put("state", l.state.name).put("detail", l.detail)
        }))
        put("exportNotice", EXPORT_NOTICE)
        put("durationMs", durationMs)
    }

    companion object {
        // Fallback only; the installed versionName is used when it can be read (Run 30).
        const val SCANNER_VERSION = "unknown"
        const val MAX_DETAIL = 120
        const val EXPORT_NOTICE = "Local diagnostic only. UNAVAILABLE or UNSUPPORTED checks were not verified and are " +
            "not evidence of safety. Play Integrity, server policy, fleet history and official signer verification " +
            "were not evaluated. Contains device model, attested OS/patch facts and check states; no serial, IMEI, " +
            "account data, file paths or secrets."
    }
}

/**
 * Local scan: create a throwaway attested key with a random challenge, verify
 * its chain on-device (Google roots + live revocation list), collect RASP
 * signals and score them with the same weights as the server. Hard
 * attestation failures force BLOCK, as on the server.
 */
class Scanner(private val context: Context) {
    private val attester = AndroidKeyAttester(context)

    /**
     * Run 31: every step runs as a [ScanTrace] phase. A failing optional step (revocation
     * list, hardware key, native collector) is recorded with its error and the scan
     * continues degraded; a failing required step propagates, and the caller still holds
     * [trace] for the debug report.
     */
    fun scan(trace: ScanTrace = ScanTrace()): ScanResult {
        val started = System.currentTimeMillis()
        val roots = trace.phase("load_attestation_roots") {
            ChainVerifier.rootKeysFromJson(
                context.assets.open("google_roots.json").use { it.readBytes().toString(Charsets.UTF_8) },
            )
        }
        val revocationStart = System.currentTimeMillis()
        // A transient failure is retried; a live list is saved, and a recent saved copy is used
        // (labelled as cached) only when every live attempt fails.
        val live = RevocationResolver.withRetry { ChainVerifier.fetchRevocationsResult().getOrThrow() }
        val cache = RevocationCache(context)
        val resolved = RevocationResolver.resolve(live, cache.load(), System.currentTimeMillis())
        if (resolved.source == RevocationSource.LIVE) cache.save(resolved.serials.orEmpty(), System.currentTimeMillis())
        trace.record("revocation_list", if (resolved.serials != null) ScanTrace.Outcome.OK else ScanTrace.Outcome.FAILED,
            System.currentTimeMillis() - revocationStart,
            revocationDetail(resolved),
            resolved.liveError)
        val revoked = resolved.serials
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val alias = "scanner_probe_" + UUID.randomUUID()
        val device = DeviceInfo.current()

        // No hardware-backed attestation at all is reported as a hard failure below; the
        // exception that caused it is kept in the trace.
        val key = try {
            trace.optional("hardware_key_generation") { attester.generate(alias, challenge) }
        } finally {
            attester.delete(alias)
        }
        val report = trace.phase("attestation_verification") {
            if (key == null) {
                AttestationReport(
                    listOf(Check("keygen", "Hardware key attestation available", Check.Status.FAIL,
                        "this device could not create an attested hardware key")),
                    null, 0, null, revoked != null,
                )
            } else {
                ChainVerifier(roots, revoked, revocationSource = resolved.source.name).verify(
                    key.chain, challenge, context.packageName,
                    mapOf(
                        "brand" to device.brand, "device" to device.device, "product" to device.product,
                        "manufacturer" to device.manufacturer, "model" to device.model,
                    ),
                )
            }
        }

        val signals = trace.phase("device_signals") { DeviceSignals(AndroidSignalProbe(context)).collect() }
        JniNativeProbe.lastError?.let { trace.record("native_collector", ScanTrace.Outcome.DEGRADED, 0, it) }
            ?: trace.record("native_collector", ScanTrace.Outcome.OK, 0)
        // JSON null must not become the string "null" (org.json's optString on NULL).
        val ownDigest = if (signals.isNull("app_signature_sha256")) null else signals.optString("app_signature_sha256").ifEmpty { null }
        val kd = report.keyDescription
        val attestedSigners = (kd?.hardwareEnforced?.appId ?: kd?.softwareEnforced?.appId)
            ?.signatureDigests?.map { d -> d.joinToString("") { "%02x".format(it) } }?.toSet().orEmpty()
        // Without attestation there is nothing to compare against; the hard failure already blocks,
        // and the report marks the signature comparison as not performed (attestedSignerAvailable).
        val attestedDigests = attestedSigners
            .ifEmpty { setOfNotNull(ownDigest) }
        val hw = kd?.hardwareEnforced
        val evidence = kd?.let {
            LocalRisk.Evidence(
                osPatchLevel = hw?.osPatchLevel,
                securityLevel = it.attestationSecurityLevel.name,
                chainType = report.chainType,
                attestedBrand = hw?.attestedIds?.get("brand"),
                attestedModel = hw?.attestedIds?.get("model"),
                osVersion = hw?.osVersion,
                vendorPatchLevel = hw?.vendorPatchLevel,
                bootPatchLevel = hw?.bootPatchLevel,
            )
        }
        val risk = trace.phase("risk_scoring") {
            LocalRisk.assess(
                signals,
                evidence,
                attestedDigests,
                reportedIds = mapOf("brand" to device.brand, "model" to device.model),
            )
        }
        val verdict = when {
            report.hardFailures.isNotEmpty() -> Verdict.BLOCK
            else -> Verdict.valueOf(risk.band)
        }
        return ScanResult(
            verdict = verdict,
            score = if (report.hardFailures.isNotEmpty()) 100 else risk.score,
            factors = risk.factors,
            attestation = report,
            signals = signals,
            device = device,
            strongBoxKey = key?.strongBox == true,
            signingDigest = ownDigest,
            durationMs = System.currentTimeMillis() - started,
            scannedAt = Date(started),
            evidence = evidence,
            attestedSignerAvailable = attestedSigners.isNotEmpty(),
            scannerVersion = runCatching { context.packageManager.getPackageInfo(context.packageName, 0).versionName }
                .getOrNull() ?: ScanResult.SCANNER_VERSION,
            trace = trace,
        )
    }
}
