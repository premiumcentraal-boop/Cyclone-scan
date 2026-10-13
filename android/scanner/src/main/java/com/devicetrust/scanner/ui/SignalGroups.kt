package com.devicetrust.scanner.ui

import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.risk.LocalRisk
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

/** Turns the raw signal report into labelled rows for display. */
fun signalGroups(signals: JSONObject, factors: List<Pair<String, Int>>): List<SignalGroup> {
    val points = factors.toMap()
    fun row(key: String): SignalRow {
        val hit = signals.optBoolean(key, false)
        val weight = LocalRisk.WEIGHTS[key] ?: 0
        return SignalRow(
            LocalRisk.DESCRIPTIONS[key] ?: key,
            when {
                !hit -> Check.Status.PASS
                weight >= 40 -> Check.Status.FAIL
                else -> Check.Status.WARN
            },
            if (hit) "detected · +${points[key] ?: weight} risk" else "not detected",
        )
    }
    val groups = GROUPS.map { (title, keys) -> SignalGroup(title, keys.map(::row)) }.toMutableList()

    val scam = groups.indexOfFirst { it.title == "Scam & remote control" }
    val remoteApps = signals.optJSONArray("env_remote_access_apps")
    val remoteNames = (0 until (remoteApps?.length() ?: 0)).map { remoteApps!!.getString(it) }
    val a11y = signals.optInt("env_a11y_third_party", 0)
    groups[scam] = groups[scam].copy(rows = groups[scam].rows + listOf(
        SignalRow("Remote-control apps installed",
            if (remoteNames.isEmpty()) Check.Status.PASS else Check.Status.WARN,
            remoteNames.joinToString().ifEmpty { "none" }),
        SignalRow("Third-party accessibility services",
            if (a11y == 0) Check.Status.PASS else Check.Status.WARN,
            if (a11y == 0) "none enabled" else "$a11y enabled"),
    ))

    val installer = if (signals.isNull("app_installer")) null else signals.optString("app_installer")
    val appRows = listOf(
        SignalRow("Installed from Google Play",
            if (installer == "com.android.vending") Check.Status.PASS else Check.Status.WARN,
            installer?.let { "installer: $it" } ?: "sideloaded (expected for this test build)"),
        SignalRow("App signature matches attested signature",
            if ("app_signature_mismatch" in points) Check.Status.FAIL else Check.Status.PASS,
            if ("app_signature_mismatch" in points) "re-signed or tampered app" else "untampered"),
    )
    groups.add(3, SignalGroup("App integrity", appRows))

    fun factorRow(key: String, okText: String) = SignalRow(
        LocalRisk.DESCRIPTIONS[key]?.substringBefore(" (") ?: key,
        if (key in points) (if ((points[key] ?: 0) >= 40) Check.Status.FAIL else Check.Status.WARN) else Check.Status.PASS,
        if (key in points) "detected · +${points[key]} risk" else okText,
    )
    groups.add(0, SignalGroup("Keybox & spoofing", listOf(
        factorRow("attestation_not_rkp_on_rkp_model", "key provenance fits this model"),
        factorRow("patch_spoofed", "reported patch matches hardware"),
        factorRow("os_version_mismatch", "reported Android version matches hardware"),
        factorRow("patch_level_inconsistent", "OS, vendor and boot patches consistent"),
    )))
    val nativeRows = com.devicetrust.client.signals.NativeSignals.CHECKS.map { key ->
        val native = signals.optString("native_" + key + "_status", "UNAVAILABLE")
        val kotlin = signals.optString("kotlin_" + key + "_comparison_status", "UNAVAILABLE")
        val comparison = signals.optString("native_" + key + "_comparison", "UNAVAILABLE")
        SignalRow(
            LocalRisk.DESCRIPTIONS[key] ?: LocalRisk.DESCRIPTIONS["native_" + key] ?: key,
            when (native) {
                "DETECTED" -> Check.Status.WARN
                "NOT_DETECTED" -> Check.Status.PASS
                else -> Check.Status.INFO
            },
            "Native: " + native + " · Kotlin comparable snapshot: " + kotlin + " · " + comparison,
        )
    }
    groups.add(0, SignalGroup("Native versus Kotlin", nativeRows + SignalRow(
        "Equivalent observations disagree",
        if (signals.optBoolean("native_kotlin_mismatch")) Check.Status.WARN else Check.Status.INFO,
        signals.optString("native_kotlin_mismatch_status", "UNAVAILABLE") +
            " · unavailable reads are not evidence of safety",
    )))
    return groups
}
