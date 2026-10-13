package com.devicetrust.client.signals

import org.json.JSONArray
import org.json.JSONObject

/** Produces the client signal report sent to the server (see service/device_trust/signals.py). */
fun interface SignalCollector {
    fun collect(): JSONObject
}

/**
 * Client-side RASP checks. Every check is best-effort and isolated: a failing
 * check reports "not detected" rather than crashing, and the server treats
 * the whole report as evidence that raises risk, never as proof of safety.
 *
 * Only booleans, counts and short identifiers are reported: no file
 * contents, no installed-app inventory beyond the fixed lists below.
 */
class DeviceSignals(private val probe: SignalProbe, private val nativeProbe: NativeProbe = JniNativeProbe) : SignalCollector {

    override fun collect(): JSONObject {
        val maps = safe { probe.readText("/proc/self/maps") }.orEmpty()
        val mapsLower = maps.lowercase()
        val build = safe { probe.build() }
        val a11y = safe { probe.enabledAccessibilityServices() }.orEmpty()
        val remoteApps = REMOTE_ACCESS_APPS.filter { (_, pkgs) -> pkgs.any { check { probe.isPackageInstalled(it) } } }
            .keys.sorted()

        return JSONObject().apply {
            put("v", 1)
            // root
            put("root_su", check { suPresent() })
            put("root_magisk", check { MAGISK_PATHS.any(probe::fileExists) || mountsMention("magisk") })
            put("root_apps", check { ROOT_APPS.any(probe::isPackageInstalled) })
            put("root_test_keys", build?.tags?.contains("test-keys") == true)
            put("root_system_rw", check { systemMountedRw() })
            // hooking
            put("hook_frida", "frida" in mapsLower || "gum-js-loop" in mapsLower || "gadget" in mapsLower)
            put("hook_frida_port", check { FRIDA_PORTS.any(probe::canConnectLoopback) })
            put("hook_xposed", check { xposedPresent(mapsLower) })
            put("hook_zygisk", "zygisk" in mapsLower)
            // debugging
            put("debug_attached", check { probe.isDebuggerConnected() })
            put("debug_traced", check { tracerPid() > 0 })
            put("debug_app_debuggable", check { probe.isAppDebuggable() })
            // emulator
            put("emu_build", build?.let(::looksLikeEmulator) == true)
            put("emu_files", check { EMULATOR_FILES.any(probe::fileExists) })
            // app integrity
            put("app_installer", safe { probe.installerPackage() } ?: JSONObject.NULL)
            put("app_signature_sha256", safe { probe.signingCertSha256() } ?: JSONObject.NULL)
            // OS facts as apps see them; the server compares them with the hardware-attested values,
            // which property-spoofing modules (e.g. PlayIntegrityFix) cannot change.
            put("os_security_patch", build?.securityPatch?.takeIf { it.isNotEmpty() } ?: JSONObject.NULL)
            put("os_release", build?.release?.takeIf { it.isNotEmpty() } ?: JSONObject.NULL)
            // environment
            put("env_dev_options", safe { probe.globalSettingInt(DEVELOPMENT_SETTINGS_ENABLED) } == 1)
            put("env_adb", safe { probe.globalSettingInt(ADB_ENABLED) } == 1)
            put("env_vpn", check { probe.isVpnActive() })
            put("env_in_call", check { probe.isInCall() })
            put("env_external_display", check { probe.hasExternalDisplay() })
            put("env_a11y_third_party", a11y.filterNot { it.isSystemApp }.map { it.packageName }.distinct().size)
            put("env_remote_access_a11y", a11y.any { s -> REMOTE_ACCESS_APPS.values.any { s.packageName in it } })
            put("env_remote_access_apps", JSONArray(remoteApps))
        }.also { NativeSignals.enrich(it, probe, nativeProbe) }
    }

    private fun suPresent(): Boolean {
        val dirs = (probe.pathDirectories() + SU_DIRS).distinct()
        return dirs.any { probe.fileExists(it.trimEnd('/') + "/su") }
    }

    private fun mountsMention(token: String): Boolean =
        probe.readText("/proc/self/mounts")?.lowercase()?.contains(token) == true

    private fun systemMountedRw(): Boolean =
        probe.readText("/proc/mounts").orEmpty().lineSequence().any { line ->
            val parts = line.split(' ')
            parts.size >= 4 && parts[1] == "/system" && parts[3].split(',').contains("rw")
        }

    private fun xposedPresent(mapsLower: String): Boolean =
        XPOSED_MAP_TOKENS.any { it in mapsLower } ||
            XPOSED_CLASSES.any(probe::classExists) ||
            probe.currentStackTrace().any { frame -> XPOSED_STACK_TOKENS.any { it in frame } }

    private fun tracerPid(): Int =
        probe.readText("/proc/self/status").orEmpty().lineSequence()
            .firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(':')?.trim()?.toIntOrNull() ?: 0

    private inline fun check(block: () -> Boolean): Boolean = try {
        block()
    } catch (_: Throwable) {
        false
    }

    private inline fun <T> safe(block: () -> T?): T? = try {
        block()
    } catch (_: Throwable) {
        null
    }

    companion object {
        const val DEVELOPMENT_SETTINGS_ENABLED = "development_settings_enabled"
        const val ADB_ENABLED = "adb_enabled"

        val SU_DIRS = listOf(
            "/system/bin", "/system/xbin", "/sbin", "/system/sbin", "/vendor/bin", "/su/bin",
            "/data/local", "/data/local/bin", "/data/local/xbin", "/system/bin/failsafe", "/odm/bin",
        )
        val MAGISK_PATHS = listOf(
            "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules", "/cache/.disable_magisk",
            "/dev/.magisk.unblock", "/debug_ramdisk/.magisk", "/data/adb/ksu", "/data/adb/ap",
        )
        /** Root managers: Magisk (+forks), KernelSU (+Next), APatch, SuperSU and legacy tools. */
        val ROOT_APPS = listOf(
            "com.topjohnwu.magisk", "io.github.huskydg.magisk", "io.github.vvb2060.magisk",
            "me.weishu.kernelsu", "com.rifsxd.ksunext", "me.bmax.apatch",
            "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.noshufou.android.su",
            "com.kingroot.kinguser", "com.thirdparty.superuser",
        )
        val FRIDA_PORTS = listOf(27042, 27043)
        val XPOSED_MAP_TOKENS = listOf("xposedbridge", "liblspd", "lspd", "edxp", "libriru", "libsandhook")
        val XPOSED_CLASSES = listOf("de.robv.android.xposed.XposedBridge", "de.robv.android.xposed.XposedHelpers")
        val XPOSED_STACK_TOKENS = listOf("de.robv.android.xposed", "LSPHooker", "EdHooker")
        val EMULATOR_FILES = listOf(
            "/dev/qemu_pipe", "/dev/goldfish_pipe", "/dev/socket/qemud", "/system/bin/qemu-props",
            "/sys/qemu_trace", "/system/lib/libc_malloc_debug_qemu.so", "/dev/socket/genyd", "/dev/socket/baseband_genyd",
        )
        /**
         * Remote-access / screen-control tools abused in "bank helpdesk" scams.
         * Reported by short name only. Each package must be listed in the
         * library manifest's <queries> to be visible on Android 11+.
         */
        val REMOTE_ACCESS_APPS: Map<String, List<String>> = mapOf(
            "anydesk" to listOf("com.anydesk.anydeskandroid"),
            "teamviewer" to listOf(
                "com.teamviewer.quicksupport.market", "com.teamviewer.teamviewer.market.mobile",
                "com.teamviewer.host.market",
            ),
            "rustdesk" to listOf("com.carriez.flutter_hbb"),
            "airdroid" to listOf("com.sand.airdroid", "com.sand.airdroidbiz"),
        )

        fun looksLikeEmulator(b: BuildInfo): Boolean {
            val fp = b.fingerprint.lowercase()
            return fp.startsWith("generic") || "emulator" in fp || "sdk_gphone" in fp || "vbox" in fp ||
                b.hardware in setOf("goldfish", "ranchu", "vbox86") ||
                b.product.contains("sdk") && (b.product.contains("google") || b.product.startsWith("sdk")) ||
                "emulator" in b.product.lowercase() || "simulator" in b.product.lowercase() ||
                b.model.contains("Emulator") || b.model.startsWith("Android SDK built for") ||
                b.manufacturer.contains("Genymotion", ignoreCase = true) ||
                (b.brand.startsWith("generic") && b.device.startsWith("generic"))
        }
    }
}
