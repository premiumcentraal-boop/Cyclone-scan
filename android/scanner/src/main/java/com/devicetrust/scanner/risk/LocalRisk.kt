package com.devicetrust.scanner.risk

import com.devicetrust.scanner.attest.ChainVerifier
import org.json.JSONObject
import java.util.Date

/**
 * On-device port of the server risk engine (service/device_trust/risk.py),
 * restricted to the inputs a phone has on its own: client signals and
 * hardware evidence. Play Integrity and history factors need the server.
 *
 * Parity with the server is enforced by testvectors/risk_vectors.json.
 */
object LocalRisk {
    const val ALLOW = "ALLOW"
    const val STEP_UP = "STEP_UP"
    const val BLOCK = "BLOCK"
    const val ALLOW_BELOW = 50
    const val BLOCK_AT = 80

    /** Same values as DEFAULT_WEIGHTS on the server, for the factors computable on-device. */
    val WEIGHTS: Map<String, Int> = mapOf(
        "root_su" to 40, "root_magisk" to 50, "root_apps" to 25, "root_test_keys" to 20, "root_system_rw" to 40,
        "hook_frida" to 70, "hook_frida_port" to 50, "hook_xposed" to 60, "hook_zygisk" to 50,
        "debug_attached" to 50, "debug_traced" to 50, "debug_app_debuggable" to 40,
        "emu_build" to 60, "emu_files" to 60,
        "app_installer_untrusted" to 30, "app_signature_mismatch" to 80,
        "env_dev_options" to 5, "env_adb" to 10, "env_vpn" to 5, "env_in_call" to 25, "env_external_display" to 30,
        "env_a11y_third_party" to 10, "env_remote_access_apps" to 15, "env_remote_access_a11y" to 45,
        "client_signals_missing" to 20,
        "os_patch_stale" to 10, "no_strongbox" to 0,
    )

    val TRUSTED_INSTALLERS = setOf("com.android.vending")
    const val STALE_PATCH_MONTHS = 6

    data class Result(val score: Int, val band: String, val factors: List<Pair<String, Int>>)

    data class Evidence(val osPatchLevel: Int?, val securityLevel: String?)

    fun assess(signals: JSONObject?, evidence: Evidence?, trustedDigests: Set<String>, now: Date = Date()): Result {
        val found = mutableListOf<String>()
        if (signals == null) {
            found += "client_signals_missing"
        } else {
            found += signals.keys().asSequence().filter { signals.opt(it) == true }.sorted()
            if (signals.optInt("env_a11y_third_party", 0) > 0) found += "env_a11y_third_party"
            if ((signals.optJSONArray("env_remote_access_apps")?.length() ?: 0) > 0) found += "env_remote_access_apps"
            if (signals.has("app_installer")) {
                val installer = if (signals.isNull("app_installer")) null else signals.getString("app_installer")
                if (installer !in TRUSTED_INSTALLERS) found += "app_installer_untrusted"
            }
            if (signals.has("app_signature_sha256") && !signals.isNull("app_signature_sha256")) {
                val digest = signals.getString("app_signature_sha256").replace(":", "").lowercase()
                if (digest.isNotEmpty() && digest !in trustedDigests) found += "app_signature_mismatch"
            }
        }
        if (evidence != null) {
            val age = evidence.osPatchLevel?.let { ChainVerifier.patchAgeMonths(it, now) }
            if (age != null && age > STALE_PATCH_MONTHS) found += "os_patch_stale"
            if (evidence.securityLevel != "STRONG_BOX") found += "no_strongbox"
        }
        val factors = found.distinct().map { it to (WEIGHTS[it] ?: 0) }
            .sortedWith(compareBy({ -it.second }, { it.first }))
        val score = minOf(100, factors.sumOf { it.second })
        val band = when {
            score >= BLOCK_AT -> BLOCK
            score >= ALLOW_BELOW -> STEP_UP
            else -> ALLOW
        }
        return Result(score, band, factors)
    }

    /** Plain-language explanation for each factor, shown in the app. */
    val DESCRIPTIONS: Map<String, String> = mapOf(
        "root_su" to "su binary found",
        "root_magisk" to "Magisk / KernelSU / APatch traces",
        "root_apps" to "Root manager app installed",
        "root_test_keys" to "OS signed with test keys",
        "root_system_rw" to "System partition writable",
        "hook_frida" to "Frida instrumentation loaded",
        "hook_frida_port" to "Frida server listening",
        "hook_xposed" to "Xposed / LSPosed hooking framework",
        "hook_zygisk" to "Zygisk module injected",
        "debug_attached" to "Debugger attached",
        "debug_traced" to "Process being traced",
        "debug_app_debuggable" to "App build is debuggable",
        "emu_build" to "Emulator build fingerprint",
        "emu_files" to "Emulator files present",
        "app_installer_untrusted" to "Not installed from Google Play",
        "app_signature_mismatch" to "App signature differs from attested one (re-signed app)",
        "env_dev_options" to "Developer options enabled",
        "env_adb" to "USB debugging (ADB) enabled",
        "env_vpn" to "VPN active",
        "env_in_call" to "Phone call in progress (scam-call risk)",
        "env_external_display" to "Screen mirrored / cast",
        "env_a11y_third_party" to "Third-party accessibility service enabled",
        "env_remote_access_apps" to "Remote-control app installed",
        "env_remote_access_a11y" to "Remote-control app has accessibility control",
        "client_signals_missing" to "No client signals",
        "os_patch_stale" to "Security patch older than 6 months",
        "no_strongbox" to "No StrongBox chip (informational)",
    )
}
