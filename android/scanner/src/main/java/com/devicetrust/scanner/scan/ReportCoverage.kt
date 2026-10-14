package com.devicetrust.scanner.scan

import com.devicetrust.client.signals.NativeSignals
import com.devicetrust.scanner.attest.AttestationReport
import com.devicetrust.scanner.risk.LocalRisk
import org.json.JSONObject

/** Where a piece of evidence came from. Local evidence is self-reported by the phone. */
enum class EvidenceSource { LOCAL_CHECK, LOCAL_NATIVE, HARDWARE_ATTESTED, SERVER }

/** Typed state of one check in the report. UNREPORTED: an older collector sent no state. */
enum class ReportState { DETECTED, NOT_DETECTED, UNAVAILABLE, UNSUPPORTED, UNREPORTED;
    val completed: Boolean get() = this == DETECTED || this == NOT_DETECTED
}

/** Outcome of one verification layer, as shown in the "Verification coverage" card. */
enum class LayerState { VERIFIED, FAILED, COMPLETE, PARTIAL, UNAVAILABLE, NOT_EVALUATED }

data class Finding(val id: String, val source: EvidenceSource, val state: ReportState, val reason: String?)

data class CoverageCounts(
    val detected: Int,
    val notDetected: Int,
    val unavailable: Int,
    val unsupported: Int,
    val unreported: Int,
) {
    val total: Int get() = detected + notDetected + unavailable + unsupported + unreported
    val completed: Int get() = detected + notDetected
    val incomplete: Int get() = total - completed

    fun toJson(): JSONObject = JSONObject().put("detected", detected).put("notDetected", notDetected)
        .put("unavailable", unavailable).put("unsupported", unsupported).put("unreported", unreported)
}

data class Layer(val id: String, val label: String, val source: EvidenceSource, val state: LayerState, val detail: String)

/** One attestation-versus-reported comparison and whether its inputs were present. */
data class Comparison(val factor: String, val comparable: Boolean, val missing: String)

/**
 * Run 14 report model: separates detected findings, completed clean checks,
 * unavailable evidence and unsupported capabilities, and says which
 * verification layers ran. Pure Kotlin so it is unit-testable; the UI and the
 * JSON export both read from here.
 */
object ReportCoverage {
    const val SCHEMA = "cyclone-scan-report"
    const val SCHEMA_VERSION = 2

    /** The Kotlin collector's detection checks (DeviceSignals), in display order. */
    val LOCAL_CHECKS = listOf(
        "root_su", "root_magisk", "root_apps", "root_test_keys", "root_system_rw",
        "hook_frida", "hook_frida_port", "hook_xposed", "hook_zygisk",
        "debug_attached", "debug_traced", "debug_app_debuggable",
        "emu_build", "emu_files",
        "env_dev_options", "env_adb", "env_vpn", "env_in_call", "env_external_display",
        "env_remote_access_a11y", "env_a11y_third_party", "env_remote_access_apps",
    )

    fun localState(signals: JSONObject, key: String): ReportState {
        val explicit = signals.optString(key + "_status", "")
        parse(explicit)?.let { return it }
        // An older collector without states: only a positive answer means anything.
        val hit = when (key) {
            "env_a11y_third_party" -> signals.optInt(key, 0) > 0
            "env_remote_access_apps" -> (signals.optJSONArray(key)?.length() ?: 0) > 0
            else -> signals.optBoolean(key, false)
        }
        return if (hit) ReportState.DETECTED else ReportState.UNREPORTED
    }

    fun nativeState(signals: JSONObject, key: String): ReportState =
        parse(signals.optString("native_" + key + "_status", "")) ?: ReportState.UNREPORTED

    private fun parse(s: String): ReportState? =
        ReportState.entries.firstOrNull { it.name == s && it != ReportState.UNREPORTED }

    /** Reason code for a non-completed check; null when the check completed or no code was sent. */
    fun reason(signals: JSONObject, key: String): String? =
        signals.optString(key + "_reason", "").takeIf { it.isNotEmpty() && it != "COMPLETED" }

    fun findings(signals: JSONObject): List<Finding> =
        LOCAL_CHECKS.map { Finding(it, EvidenceSource.LOCAL_CHECK, localState(signals, it), reason(signals, it)) } +
            NativeSignals.CHECKS.map { Finding("native_$it", EvidenceSource.LOCAL_NATIVE, nativeState(signals, it), null) }

    fun counts(findings: List<Finding>, source: EvidenceSource): CoverageCounts {
        val states = findings.filter { it.source == source }.map { it.state }
        return CoverageCounts(
            detected = states.count { it == ReportState.DETECTED },
            notDetected = states.count { it == ReportState.NOT_DETECTED },
            unavailable = states.count { it == ReportState.UNAVAILABLE },
            unsupported = states.count { it == ReportState.UNSUPPORTED },
            unreported = states.count { it == ReportState.UNREPORTED },
        )
    }

    /** Plain-language explanation for a reason code; never includes paths or raw OS output. */
    fun reasonText(reason: String?): String = when (reason) {
        "ACCESS_DENIED" -> "Android did not allow this app to read it (normal under app sandboxing)"
        "PARTIAL_COVERAGE" -> "only some sources could be read"
        "READ_ERROR" -> "the information could not be read"
        "MALFORMED" -> "the information was in an unexpected format"
        "TOO_LARGE" -> "the information was larger than the safe read limit"
        "API_ERROR" -> "the Android query failed"
        "API_UNSUPPORTED" -> "not supported on this Android version"
        else -> "no reason reported"
    }

    /** Attestation-versus-reported comparisons in the "Keybox & spoofing" group. */
    fun comparisons(evidence: LocalRisk.Evidence?, signals: JSONObject): List<Comparison> {
        val noAttestation = "no hardware attestation evidence"
        val patch = signals.takeUnless { it.isNull("os_security_patch") }?.optString("os_security_patch", "").orEmpty()
        val release = signals.takeUnless { it.isNull("os_release") }?.optString("os_release", "").orEmpty()
        val major = release.substringBefore('.')
        return listOf(
            Comparison("attestation_not_rkp_on_rkp_model", evidence?.chainType != null,
                if (evidence == null) noAttestation else "key provenance could not be classified"),
            Comparison("patch_spoofed", evidence?.osPatchLevel != null && patch.length >= 7 &&
                patch.substring(0, 4).all(Char::isDigit) && patch.substring(5, 7).all(Char::isDigit),
                when {
                    evidence == null -> noAttestation
                    evidence.osPatchLevel == null -> "hardware did not attest a patch level"
                    else -> "the phone did not report a readable security patch"
                }),
            Comparison("os_version_mismatch",
                evidence?.osVersion?.let { it > 0 } == true && major.isNotEmpty() && major.all(Char::isDigit),
                when {
                    evidence == null -> noAttestation
                    (evidence.osVersion ?: 0) <= 0 -> "hardware did not attest an OS version"
                    else -> "the reported Android version is not numeric (pre-release builds use codenames)"
                }),
            Comparison("patch_level_inconsistent",
                evidence?.osPatchLevel != null && (evidence.vendorPatchLevel != null || evidence.bootPatchLevel != null),
                if (evidence == null) noAttestation else "vendor and boot patch levels were not attested"),
        )
    }

    /** What ran in this local scan, and what explicitly did not. */
    fun layers(attestation: AttestationReport, findings: List<Finding>): List<Layer> {
        val att = when {
            attestation.keyDescription == null && attestation.checks.any { it.id == "keygen" } ->
                Layer("hardware_attestation", "Hardware key attestation", EvidenceSource.HARDWARE_ATTESTED,
                    LayerState.UNAVAILABLE, "this phone could not create an attested hardware key")
            attestation.hardFailures.isNotEmpty() ->
                Layer("hardware_attestation", "Hardware key attestation", EvidenceSource.HARDWARE_ATTESTED,
                    LayerState.FAILED, "${attestation.hardFailures.size} hard check(s) failed or could not be established")
            else -> Layer("hardware_attestation", "Hardware key attestation", EvidenceSource.HARDWARE_ATTESTED,
                LayerState.VERIFIED, "chain verified on this phone against Google's attestation roots")
        }
        val revocation = Layer("revocation_list", "Google revocation list", EvidenceSource.HARDWARE_ATTESTED,
            if (attestation.revocationChecked) LayerState.VERIFIED else LayerState.UNAVAILABLE,
            if (attestation.revocationChecked) "downloaded and checked" else "could not be downloaded, so revocation is not established")
        fun checksLayer(id: String, label: String, source: EvidenceSource): Layer {
            val c = counts(findings, source)
            val state = when {
                c.total == 0 || c.completed == 0 -> LayerState.UNAVAILABLE
                c.incomplete == 0 -> LayerState.COMPLETE
                else -> LayerState.PARTIAL
            }
            return Layer(id, label, source, state,
                "${c.completed} of ${c.total} completed · ${c.unavailable + c.unreported} could not be verified · " +
                    "${c.unsupported} unsupported")
        }
        val notLocal = "requires the verification server; not run in local mode"
        return listOf(
            att,
            revocation,
            checksLayer("local_checks", "On-phone checks (Kotlin)", EvidenceSource.LOCAL_CHECK),
            checksLayer("native_checks", "On-phone checks (native)", EvidenceSource.LOCAL_NATIVE),
            Layer("play_integrity", "Google Play Integrity", EvidenceSource.SERVER, LayerState.NOT_EVALUATED, notLocal),
            Layer("server_policy", "Server policy decision", EvidenceSource.SERVER, LayerState.NOT_EVALUATED, notLocal),
            Layer("fleet_history", "Device and fleet history", EvidenceSource.SERVER, LayerState.NOT_EVALUATED, notLocal),
            Layer("official_signer", "Official scanner signer", EvidenceSource.SERVER, LayerState.NOT_EVALUATED,
                "the app compares its signer only with its own attestation; that is not independent verification"),
        )
    }
}
