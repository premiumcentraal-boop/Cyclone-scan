package com.devicetrust.scanner.scan

import android.content.Context
import com.devicetrust.client.AndroidKeyAttester
import com.devicetrust.client.DeviceInfo
import com.devicetrust.scanner.attest.AttestationReport
import com.devicetrust.scanner.attest.ChainVerifier
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.risk.LocalRisk
import com.devicetrust.client.signals.AndroidSignalProbe
import com.devicetrust.client.signals.DeviceSignals
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Date
import java.util.UUID

enum class Verdict { ALLOW, STEP_UP, BLOCK }

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
) {
    val hardFailures: List<Check> get() = attestation.hardFailures

    fun toJson(): JSONObject = JSONObject().apply {
        put("scanner", "device-trust-scanner/0.6.0")
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
                JSONObject().put("id", it.id).put("status", it.status.name).put("detail", it.detail)
            }))
        })
        put("signals", signals)
        put("durationMs", durationMs)
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

    fun scan(): ScanResult {
        val started = System.currentTimeMillis()
        val roots = ChainVerifier.rootKeysFromJson(
            context.assets.open("google_roots.json").use { it.readBytes().toString(Charsets.UTF_8) },
        )
        val revoked = ChainVerifier.fetchRevocations()
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val alias = "scanner_probe_" + UUID.randomUUID()
        val device = DeviceInfo.current()

        val key = try {
            attester.generate(alias, challenge)
        } catch (e: Exception) {
            null // no hardware-backed attestation at all: reported as a hard failure below
        } finally {
            attester.delete(alias)
        }
        val report = if (key == null) {
            AttestationReport(
                listOf(Check("keygen", "Hardware key attestation available", Check.Status.FAIL,
                    "this device could not create an attested hardware key")),
                null, 0, null, revoked != null,
            )
        } else {
            ChainVerifier(roots, revoked).verify(
                key.chain, challenge, context.packageName,
                mapOf(
                    "brand" to device.brand, "device" to device.device, "product" to device.product,
                    "manufacturer" to device.manufacturer, "model" to device.model,
                ),
            )
        }

        val signals = DeviceSignals(AndroidSignalProbe(context)).collect()
        val kd = report.keyDescription
        val attestedDigests = (kd?.hardwareEnforced?.appId ?: kd?.softwareEnforced?.appId)
            ?.signatureDigests?.map { d -> d.joinToString("") { "%02x".format(it) } }?.toSet().orEmpty()
            // Without attestation there is nothing to compare against; the hard failure already blocks.
            .ifEmpty { setOfNotNull(signals.optString("app_signature_sha256").ifEmpty { null }) }
        val hw = kd?.hardwareEnforced
        val risk = LocalRisk.assess(
            signals,
            kd?.let {
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
            },
            attestedDigests,
            reportedIds = mapOf("brand" to device.brand, "model" to device.model),
        )
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
            signingDigest = signals.optString("app_signature_sha256").ifEmpty { null },
            durationMs = System.currentTimeMillis() - started,
            scannedAt = Date(started),
        )
    }
}
