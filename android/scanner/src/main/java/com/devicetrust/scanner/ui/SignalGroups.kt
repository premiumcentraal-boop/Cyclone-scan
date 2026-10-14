package com.devicetrust.scanner.ui

import com.devicetrust.client.signals.NativeSignals
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.risk.LocalRisk
import com.devicetrust.scanner.scan.ReportCoverage
import com.devicetrust.scanner.scan.ReportState
import org.json.JSONObject

data class SignalRow(val label: String, val status: Check.Status, val detail: String = "")
data class SignalGroup(val title: String, val rows: List<SignalRow>)

private val GROUPS = listOf(
    "Root" to listOf("root_su", "root_magisk", "root_apps", "root_test_keys", "root_system_rw"),
    "Hooking & debugging" to listOf(
        "hook_frida", "hook_frida_port", "hook_xposed", "hook_zygisk",
        "debug_attached", "debug_traced", "debug_app_debuggable",
    ),
    "Emulator" to listOf("emu_build", "emu_files"),
    "Scam & remote control" to listOf("env_in_call", "env_external_display", "env_remote_access_a11y"),
    "Device settings" to listOf("env_dev_options", "env_adb", "env_vpn"),
)

/** Detail text for a check that did not complete. Never claims the check passed. */
fun unverifiedDetail(state: ReportState, reason: String?): String = when (state) {
    ReportState.UNSUPPORTED -> "not supported on this device · not evidence of safety"
    ReportState.UNREPORTED -> "not reported by this collector · not evidence of safety"
    else -> "could not verify: " + ReportCoverage.reasonText(reason) + " · not evidence of safety"
}

/**
 * Turns the raw signal report into labelled rows for display (Run 14):
 * DETECTED rows are findings, NOT_DETECTED rows are completed clean checks,
 * and anything else is UNVERIFIED with its reason, never a green pass.
 */
fun signalGroups(
    signals: JSONObject,
    factors: List<Pair<String, Int>>,
    evidence: LocalRisk.Evidence? = null,
    attestedSignerAvailable: Boolean = false,
): List<SignalGroup> {
    val points = factors.toMap()
    fun row(key: String): SignalRow {
        val state = ReportCoverage.localState(signals, key)
        val weight = LocalRisk.WEIGHTS[key] ?: 0
        val label = LocalRisk.DESCRIPTIONS[key] ?: key
        return when (state) {
            ReportState.DETECTED -> SignalRow(label, if (weight >= 40) Check.Status.FAIL else Check.Status.WARN,
                "detected · +${points[key] ?: weight} risk")
            ReportState.NOT_DETECTED -> SignalRow(label, Check.Status.PASS, "not detected")
            else -> SignalRow(label, Check.Status.UNVERIFIED, unverifiedDetail(state, ReportCoverage.reason(signals, key)))
        }
    }
    val groups = GROUPS.map { (title, keys) -> SignalGroup(title, keys.map(::row)) }.toMutableList()

    val scam = groups.indexOfFirst { it.title == "Scam & remote control" }
    val remoteApps = signals.optJSONArray("env_remote_access_apps")
    val remoteNames = (0 until (remoteApps?.length() ?: 0)).map { remoteApps!!.getString(it) }
    val remoteState = ReportCoverage.localState(signals, "env_remote_access_apps")
    val a11y = signals.optInt("env_a11y_third_party", 0)
    val a11yState = ReportCoverage.localState(signals, "env_a11y_third_party")
    groups[scam] = groups[scam].copy(rows = groups[scam].rows + listOf(
        when (remoteState) {
            ReportState.DETECTED -> SignalRow("Remote-control apps installed", Check.Status.WARN, remoteNames.joinToString())
            ReportState.NOT_DETECTED -> SignalRow("Remote-control apps installed", Check.Status.PASS, "none of the listed apps")
            else -> SignalRow("Remote-control apps installed", Check.Status.UNVERIFIED,
                unverifiedDetail(remoteState, ReportCoverage.reason(signals, "env_remote_access_apps")))
        },
        when (a11yState) {
            ReportState.DETECTED -> SignalRow("Third-party accessibility services", Check.Status.WARN, "$a11y enabled")
            ReportState.NOT_DETECTED -> SignalRow("Third-party accessibility services", Check.Status.PASS, "none enabled")
            else -> SignalRow("Third-party accessibility services", Check.Status.UNVERIFIED,
                unverifiedDetail(a11yState, ReportCoverage.reason(signals, "env_a11y_third_party")))
        },
    ))

    groups.add(3, SignalGroup("App integrity", listOf(installerRow(signals), signatureRow(signals, points, attestedSignerAvailable))))

    val comparisons = ReportCoverage.comparisons(evidence, signals).associateBy { it.factor }
    fun factorRow(key: String, okText: String): SignalRow {
        val label = LocalRisk.DESCRIPTIONS[key]?.substringBefore(" (") ?: key
        val comparison = comparisons[key]
        return when {
            key in points -> SignalRow(label, if ((points[key] ?: 0) >= 40) Check.Status.FAIL else Check.Status.WARN,
                "detected · +${points[key]} risk")
            comparison != null && !comparison.comparable ->
                SignalRow(label, Check.Status.UNVERIFIED, "not compared: ${comparison.missing}")
            else -> SignalRow(label, Check.Status.PASS, okText)
        }
    }
    groups.add(0, SignalGroup("Keybox & spoofing", listOf(
        factorRow("attestation_not_rkp_on_rkp_model", "key provenance fits this model"),
        factorRow("patch_spoofed", "reported patch matches hardware"),
        factorRow("os_version_mismatch", "reported Android version matches hardware"),
        factorRow("patch_level_inconsistent", "OS, vendor and boot patches consistent"),
    )))
    val nativeRows = NativeSignals.CHECKS.map { key ->
        val native = signals.optString("native_" + key + "_status", "UNAVAILABLE")
        val kotlin = signals.optString("kotlin_" + key + "_comparison_status", "UNAVAILABLE")
        val comparison = signals.optString("native_" + key + "_comparison", "UNAVAILABLE")
        SignalRow(
            LocalRisk.DESCRIPTIONS[key] ?: LocalRisk.DESCRIPTIONS["native_" + key] ?: key,
            when (native) {
                "DETECTED" -> Check.Status.WARN
                "NOT_DETECTED" -> Check.Status.PASS
                else -> Check.Status.UNVERIFIED
            },
            "Native: " + native + " · Kotlin comparable snapshot: " + kotlin + " · " + comparison,
        )
    }
    groups.add(0, SignalGroup("Native versus Kotlin", nativeRows + SignalRow(
        "Equivalent observations disagree",
        when (signals.optString("native_kotlin_mismatch_status", "UNAVAILABLE")) {
            "DETECTED" -> Check.Status.WARN
            "NOT_DETECTED" -> Check.Status.PASS
            else -> Check.Status.UNVERIFIED
        },
        signals.optString("native_kotlin_mismatch_status", "UNAVAILABLE") +
            " · unavailable reads are not evidence of safety",
    )))
    return groups
}

private fun valueState(signals: JSONObject, key: String): String = signals.optString(key + "_status", "")

private fun installerRow(signals: JSONObject): SignalRow {
    val label = "Installed from Google Play"
    val state = valueState(signals, "app_installer")
    if (state == "UNAVAILABLE" || state == "UNSUPPORTED") {
        return SignalRow(label, Check.Status.UNVERIFIED,
            "installer could not be read: " + ReportCoverage.reasonText(ReportCoverage.reason(signals, "app_installer")))
    }
    val installer = if (signals.isNull("app_installer")) null else signals.optString("app_installer").ifEmpty { null }
    return when {
        installer == "com.android.vending" -> SignalRow(label, Check.Status.PASS, "installer: $installer")
        installer != null -> SignalRow(label, Check.Status.WARN, "installer: $installer")
        else -> SignalRow(label, Check.Status.WARN, "no installer recorded (sideloaded; expected for this test build)")
    }
}

private fun signatureRow(signals: JSONObject, points: Map<String, Int>, attestedSignerAvailable: Boolean): SignalRow {
    val label = "App signature matches attested signature"
    val unreadable = valueState(signals, "app_signature_sha256").let { it == "UNAVAILABLE" || it == "UNSUPPORTED" } ||
        signals.isNull("app_signature_sha256")
    return when {
        "app_signature_mismatch" in points -> SignalRow(label, Check.Status.FAIL, "re-signed or tampered app")
        unreadable -> SignalRow(label, Check.Status.UNVERIFIED, "not compared: this app's signing certificate could not be read")
        !attestedSignerAvailable -> SignalRow(label, Check.Status.UNVERIFIED, "not compared: the attestation did not list a signer")
        else -> SignalRow(label, Check.Status.PASS,
            "matches the signer in this app's own attestation (self-consistency, not official signer verification)")
    }
}
