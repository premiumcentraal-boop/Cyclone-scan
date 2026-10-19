package com.devicetrust.client.signals

import org.json.JSONArray
import org.json.JSONObject

/** Produces the client signal report sent to the server (see service/device_trust/signals.py). */
fun interface SignalCollector {
    fun collect(): JSONObject
}

/**
 * Hook frameworks (Frida, Xposed/LSPosed, Zygisk) inject only into the processes they target.
 * The scanner reads its own process, so "not found here" says nothing about the rest of the
 * phone. That result is reported as partial coverage, never as a clean check. A detection is
 * still a detection.
 */
internal fun scopedToThisProcess(result: CheckResult): CheckResult =
    if (result.state == CheckState.NOT_DETECTED) CheckResult.unavailable(CheckReason.SCOPE_LIMITED) else result

/**
 * Client-side RASP checks. Every check is best-effort and isolated: a failing
 * check never crashes collection. Since Run 14 each check also reports a
 * typed `<key>_status` (DETECTED / NOT_DETECTED / UNAVAILABLE / UNSUPPORTED)
 * and a bounded `<key>_reason`, so a denied read is reported as "could not
 * verify", never as a clean result. The boolean stays `false` for anything
 * other than DETECTED, which keeps the v1 wire format and scoring unchanged.
 * The server treats the whole report as evidence that raises risk, never as
 * proof of safety.
 *
 * Only booleans, counts, states and short identifiers are reported: no file
 * contents, paths, memory maps or installed-app inventory beyond the fixed
 * lists below.
 */
class DeviceSignals(private val probe: SignalProbe, private val nativeProbe: NativeProbe = JniNativeProbe) : SignalCollector {

    override fun collect(): JSONObject {
        val maps = read("/proc/self/maps")
        val mapsLower = (maps as? TextRead.Ok)?.text?.lowercase()
        val build: Result<BuildInfo> = runCatching { probe.build() }
        val a11y: Result<List<AccessibilityServiceRef>> = runCatching { probe.enabledAccessibilityServices() }
        val remoteParts = REMOTE_ACCESS_APPS.mapValues { (_, pkgs) -> CheckResult.anyOf(pkgs.map { observe { probe.isPackageInstalled(it) } }) }
        val remoteApps = remoteParts.filterValues { it.detected }.keys.sorted()

        val report = JSONObject().put("v", 1).put("signal_coverage_version", COVERAGE_VERSION)
        fun flag(key: String, result: CheckResult) {
            report.put(key, result.detected)
            report.put(key + "_status", result.state.name)
            report.put(key + "_reason", result.reason.name)
        }
        fun value(key: String, result: Result<String?>) {
            val v = result.getOrNull()
            report.put(key, v ?: JSONObject.NULL)
            val failure = result.exceptionOrNull()
            val (state, reason) = when {
                failure == null -> ValueState.COLLECTED to CheckReason.COMPLETED
                failure is MissingValue -> ValueState.UNAVAILABLE to CheckReason.READ_ERROR
                else -> CheckResult.failure(failure).let {
                    (if (it.state == CheckState.UNSUPPORTED) ValueState.UNSUPPORTED else ValueState.UNAVAILABLE) to it.reason
                }
            }
            report.put(key + "_status", state.name)
            report.put(key + "_reason", reason.name)
        }
        fun mapsCheck(test: (String) -> Boolean): CheckResult = when {
            mapsLower != null -> CheckResult.of(test(mapsLower))
            else -> CheckResult.unavailable((maps as TextRead.Failed).reason)
        }
        fun buildCheck(test: (BuildInfo) -> Boolean): CheckResult =
            build.fold({ b -> observe { test(b) } }, { CheckResult.failure(it) })
        fun setting(name: String): CheckResult = try {
            probe.globalSettingInt(name)?.let { CheckResult.of(it == 1) } ?: CheckResult.unavailable(CheckReason.READ_ERROR)
        } catch (t: Throwable) {
            CheckResult.failure(t)
        }

        // root
        flag("root_su", paths(suDirs().map { it.trimEnd('/') + "/su" }))
        flag("root_magisk", CheckResult.anyOf(listOf(paths(MAGISK_PATHS), textCheck("/proc/self/mounts") { "magisk" in it.lowercase() })))
        flag("root_apps", CheckResult.anyOf(ROOT_APPS.map { observe { probe.isPackageInstalled(it) } }))
        flag("root_test_keys", buildCheck { it.tags.contains("test-keys") })
        flag("root_system_rw", textCheck("/proc/mounts", ::systemMountedRw))
        // hooking
        flag("hook_frida", scopedToThisProcess(mapsCheck { m -> "frida" in m || "gum-js-loop" in m || "gadget" in m }))
        flag("hook_frida_port", CheckResult.anyOf(FRIDA_PORTS.map { observe { probe.canConnectLoopback(it) } }))
        flag("hook_xposed", scopedToThisProcess(CheckResult.anyOf(
            listOf(mapsCheck { m -> XPOSED_MAP_TOKENS.any { it in m } }) +
                XPOSED_CLASSES.map { observe { probe.classExists(it) } } +
                observe { probe.currentStackTrace().any { frame -> XPOSED_STACK_TOKENS.any { it in frame } } },
        )))
        flag("hook_zygisk", scopedToThisProcess(mapsCheck { "zygisk" in it }))
        // debugging
        flag("debug_attached", observe { probe.isDebuggerConnected() })
        flag("debug_traced", tracer())
        flag("debug_app_debuggable", observe { probe.isAppDebuggable() })
        // emulator
        flag("emu_build", buildCheck(::looksLikeEmulator))
        flag("emu_files", paths(EMULATOR_FILES))
        // app integrity
        value("app_installer", runCatching { probe.installerPackage() })
        value("app_signature_sha256", runCatching { probe.signingCertSha256() ?: throw MissingValue() })
        // OS facts as apps see them; the server compares them with the hardware-attested values,
        // which property-spoofing modules (e.g. PlayIntegrityFix) cannot change. An empty
        // Build value is reported as null/UNAVAILABLE rather than as a fact.
        value("os_security_patch", build.mapCatching { it.securityPatch.ifEmpty { throw MissingValue() } })
        value("os_release", build.mapCatching { it.release.ifEmpty { throw MissingValue() } })
        // environment
        flag("env_dev_options", setting(DEVELOPMENT_SETTINGS_ENABLED))
        flag("env_adb", setting(ADB_ENABLED))
        flag("env_vpn", observe { probe.isVpnActive() })
        flag("env_in_call", observe { probe.isInCall() })
        flag("env_external_display", observe { probe.hasExternalDisplay() })
        val a11yServices = a11y.getOrNull().orEmpty()
        val a11yResult = a11y.fold({ CheckResult.NOT_DETECTED }, { CheckResult.failure(it) })
        val thirdParty = a11yServices.filterNot { it.isSystemApp }.map { it.packageName }.distinct().size
        report.put("env_a11y_third_party", thirdParty)
        report.put("env_a11y_third_party_status", (if (thirdParty > 0) CheckResult.DETECTED else a11yResult).state.name)
        report.put("env_a11y_third_party_reason", (if (thirdParty > 0) CheckResult.DETECTED else a11yResult).reason.name)
        flag("env_remote_access_a11y",
            if (a11yServices.any { s -> REMOTE_ACCESS_APPS.values.any { s.packageName in it } }) CheckResult.DETECTED else a11yResult)
        val remote = CheckResult.anyOf(remoteParts.values.toList())
        report.put("env_remote_access_apps", JSONArray(remoteApps))
        report.put("env_remote_access_apps_status", remote.state.name)
        report.put("env_remote_access_apps_reason", remote.reason.name)
        return report.also { NativeSignals.enrich(it, probe, nativeProbe) }
    }

    /** A query that completed without a usable value (e.g. empty Build field, no signing certificate). */
    private class MissingValue : RuntimeException()

    private fun read(path: String): TextRead = try {
        probe.readTextResult(path)
    } catch (t: Throwable) {
        TextRead.Failed(CheckResult.failure(t).reason)
    }

    private fun textCheck(path: String, test: (String) -> Boolean): CheckResult = when (val r = read(path)) {
        is TextRead.Ok -> observe { test(r.text) }
        is TextRead.Failed -> CheckResult.unavailable(r.reason)
    }

    private fun paths(list: List<String>): CheckResult = CheckResult.anyOf(list.map { path ->
        try {
            probe.pathState(path).toResult()
        } catch (t: Throwable) {
            CheckResult.failure(t)
        }
    })

    private fun suDirs(): List<String> =
        ((runCatching { probe.pathDirectories() }.getOrNull() ?: emptyList()) + SU_DIRS).distinct()

    private fun systemMountedRw(mounts: String): Boolean =
        mounts.lineSequence().any { line ->
            val parts = line.split(' ')
            parts.size >= 4 && parts[1] == "/system" && parts[3].split(',').contains("rw")
        }

    /** TracerPid from /proc/self/status; a missing or garbled line is MALFORMED, not "not traced". */
    private fun tracer(): CheckResult = when (val r = read("/proc/self/status")) {
        is TextRead.Failed -> CheckResult.unavailable(r.reason)
        is TextRead.Ok -> r.text.lineSequence().firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(':')?.trim()?.toIntOrNull()?.takeIf { it >= 0 }
            ?.let { CheckResult.of(it > 0) }
            ?: CheckResult.unavailable(CheckReason.MALFORMED)
    }

    companion object {
        /** Version of the additive `_status` / `_reason` fields; the wire format stays "v": 1. */
        const val COVERAGE_VERSION = 1
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
