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
    val NATIVE_ALIASES = mapOf(
        "native_root_su" to "root_su",
        "native_root_magisk" to "root_magisk",
        "native_root_system_rw" to "root_system_rw",
        "native_hook_frida" to "hook_frida",
        "native_hook_xposed" to "hook_xposed",
        "native_hook_zygisk" to "hook_zygisk",
        "native_debug_traced" to "debug_traced"
    )

    val WEIGHTS: Map<String, Int> = mapOf(
        "native_selinux_permissive" to 20, "native_code_modified" to 60, "native_kotlin_mismatch" to 40,
        "root_su" to 40, "root_magisk" to 50, "root_apps" to 25, "root_test_keys" to 20, "root_system_rw" to 40,
        "hook_frida" to 70, "hook_frida_port" to 50, "hook_xposed" to 60, "hook_zygisk" to 50,
        "debug_attached" to 50, "debug_traced" to 50, "debug_app_debuggable" to 40,
        "emu_build" to 60, "emu_files" to 60,
        "app_installer_untrusted" to 30, "app_signature_mismatch" to 80,
        "env_dev_options" to 5, "env_adb" to 10, "env_vpn" to 5, "env_in_call" to 25, "env_external_display" to 30,
        "env_a11y_third_party" to 10, "env_remote_access_apps" to 15, "env_remote_access_a11y" to 45,
        "client_signals_missing" to 20,
        "attestation_not_rkp_on_rkp_model" to 80, "attestation_factory_keybox_modern_os" to 10,
        "patch_spoofed" to 50, "os_version_mismatch" to 40, "patch_level_inconsistent" to 10,
        "os_patch_stale" to 10, "no_strongbox" to 0,
    )

    /** Same list as DEFAULT_RKP_REQUIRED_MODELS on the server ("brand/model", lowercase). */
    val RKP_REQUIRED_MODELS: Set<String> = listOf(
        "Pixel 7", "Pixel 7 Pro", "Pixel 7a", "Pixel Fold", "Pixel Tablet",
        "Pixel 8", "Pixel 8 Pro", "Pixel 8a",
        "Pixel 9", "Pixel 9 Pro", "Pixel 9 Pro XL", "Pixel 9 Pro Fold", "Pixel 9a",
        "Pixel 10", "Pixel 10 Pro", "Pixel 10 Pro XL", "Pixel 10 Pro Fold",
    ).map { "google/" + it.lowercase() }.toSet()
    const val MODERN_OS_MAJOR = 14
    const val PATCH_INCONSISTENCY_MONTHS = 24

    val TRUSTED_INSTALLERS = setOf("com.android.vending")
    const val STALE_PATCH_MONTHS = 6

    data class Result(val score: Int, val band: String, val factors: List<Pair<String, Int>>)

    data class Evidence(
        val osPatchLevel: Int?,
        val securityLevel: String?,
        val chainType: String? = null,
        val attestedBrand: String? = null,
        val attestedModel: String? = null,
        val osVersion: Int? = null,
        val vendorPatchLevel: Int? = null,
        val bootPatchLevel: Int? = null,
    )

    fun assess(
        signals: JSONObject?,
        evidence: Evidence?,
        trustedDigests: Set<String>,
        now: Date = Date(),
        reportedIds: Map<String, String>? = null,
    ): Result {
        val found = mutableListOf<String>()
        if (signals == null) {
            found += "client_signals_missing"
        } else {
            found += signals.keys().asSequence().filter { signals.opt(it) == true && !it.startsWith("native_") }.sorted()
            NATIVE_ALIASES.forEach { (key, factor) ->
                if (signals.optBoolean(key) && signals.optString(key + "_status") == "DETECTED") found += factor
            }
            listOf("native_selinux_permissive", "native_code_modified", "native_kotlin_mismatch").forEach { factor ->
                if (signals.optBoolean(factor) && signals.optString(factor + "_status") == "DETECTED") found += factor
            }
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
            found += provenanceFactors(evidence, reportedIds)
            found += consistencyFactors(evidence, signals)
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

    private fun monthIndex(level: Int): Int? {
        val ym = if (level > 999_999) level / 100 else level
        val year = ym / 100
        val month = ym % 100
        if (month !in 1..12 || year < 2000) return null
        return year * 12 + month - 1
    }

    fun modelKey(e: Evidence, reported: Map<String, String>?): String? {
        var brand = e.attestedBrand
        var model = e.attestedModel
        if (brand.isNullOrEmpty() || model.isNullOrEmpty()) {
            brand = reported?.get("brand")
            model = reported?.get("model")
        }
        return if (!brand.isNullOrEmpty() && !model.isNullOrEmpty()) "$brand/$model".lowercase() else null
    }

    private fun provenanceFactors(e: Evidence, reported: Map<String, String>?): List<String> {
        if (e.chainType != "FACTORY") return emptyList()
        val out = mutableListOf<String>()
        if (modelKey(e, reported) in RKP_REQUIRED_MODELS) out += "attestation_not_rkp_on_rkp_model"
        if (e.osVersion != null && e.osVersion / 10000 >= MODERN_OS_MAJOR) out += "attestation_factory_keybox_modern_os"
        return out
    }

    private fun consistencyFactors(e: Evidence, client: JSONObject?): List<String> {
        val out = mutableListOf<String>()
        val attested = e.osPatchLevel?.let(::monthIndex)
        for (other in listOf(e.vendorPatchLevel, e.bootPatchLevel)) {
            val m = other?.let(::monthIndex)
            if (attested != null && m != null && kotlin.math.abs(attested - m) > PATCH_INCONSISTENCY_MONTHS) {
                out += "patch_level_inconsistent"
                break
            }
        }
        if (client != null) {
            val patch = if (client.isNull("os_security_patch")) null else client.optString("os_security_patch", "")
            if (attested != null && patch != null && patch.length >= 7) {
                val year = patch.substring(0, 4).toIntOrNull()
                val month = patch.substring(5, 7).toIntOrNull()
                val reported = if (year != null && month != null) monthIndex(year * 100 + month) else null
                if (reported != null && reported != attested) out += "patch_spoofed"
            }
            val release = if (client.isNull("os_release")) null else client.optString("os_release", "")
            val major = release?.substringBefore('.')
            if (major != null && major.isNotEmpty() && major.all(Char::isDigit) && e.osVersion != null && e.osVersion > 0 &&
                major.toInt() != e.osVersion / 10000
            ) {
                out += "os_version_mismatch"
            }
        }
        return out
    }

    /** Plain-language explanation for each factor, shown in the app. */
    val DESCRIPTIONS: Map<String, String> = mapOf(
        "native_selinux_permissive" to "SELinux enforcement disabled (native)",
        "native_code_modified" to "SDK code changed since library load",
        "native_kotlin_mismatch" to "Native and Kotlin equivalent observations disagree",
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
        "attestation_not_rkp_on_rkp_model" to "Factory keybox on a phone that only uses Google RKP keys (leaked keybox?)",
        "attestation_factory_keybox_modern_os" to "Factory keybox instead of Google-provisioned key on Android 14+",
        "patch_spoofed" to "Reported security patch differs from the hardware-attested one",
        "os_version_mismatch" to "Reported Android version differs from the hardware-attested one",
        "patch_level_inconsistent" to "OS, vendor and boot patch levels far apart",
        "os_patch_stale" to "Security patch older than 6 months",
        "no_strongbox" to "No StrongBox chip (informational)",
    )
}
