package com.devicetrust.client.signals

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

private val PIXEL = BuildInfo(
    tags = "release-keys",
    fingerprint = "google/shiba/shiba:16/BP2A.250805.005/13691446:user/release-keys",
    hardware = "shiba", product = "shiba", model = "Pixel 8", manufacturer = "Google",
    brand = "google", device = "shiba", securityPatch = "2026-09-05", release = "16",
)

/** Clean phone by default; tests flip individual answers. */
open class FakeProbe : SignalProbe {
    val files = mutableSetOf<String>()
    val texts = mutableMapOf<String, String>()
    val packages = mutableSetOf<String>()
    val settings = mutableMapOf<String, Int>()
    var a11y = listOf<AccessibilityServiceRef>()
    var buildInfo = PIXEL
    var debugger = false
    var debuggable = false
    var installer: String? = "com.android.vending"
    var signature: String? = "ab".repeat(32)
    val openPorts = mutableSetOf<Int>()
    val classes = mutableSetOf<String>()
    var stack = listOf("com.bank.MainActivity.onCreate")
    var vpn = false
    var inCall = false
    var externalDisplay = false

    override fun fileExists(path: String) = path in files
    override fun readText(path: String) = texts[path]
    override fun pathDirectories() = listOf("/product/bin", "/apex/com.android.runtime/bin")
    override fun build() = buildInfo
    override fun isPackageInstalled(packageName: String) = packageName in packages
    override fun globalSettingInt(name: String) = settings[name]
    override fun enabledAccessibilityServices() = a11y
    override fun isDebuggerConnected() = debugger
    override fun isAppDebuggable() = debuggable
    override fun installerPackage() = installer
    override fun signingCertSha256() = signature
    override fun canConnectLoopback(port: Int) = port in openPorts
    override fun classExists(name: String) = name in classes
    override fun currentStackTrace() = stack
    override fun isVpnActive() = vpn
    override fun isInCall() = inCall
    override fun hasExternalDisplay() = externalDisplay
}

class DeviceSignalsTest {
    private fun collect(setup: FakeProbe.() -> Unit = {}): JSONObject = DeviceSignals(FakeProbe().apply(setup)).collect()

    private val boolKeys = listOf(
        "root_su", "root_magisk", "root_apps", "root_test_keys", "root_system_rw",
        "hook_frida", "hook_frida_port", "hook_xposed", "hook_zygisk",
        "debug_attached", "debug_traced", "debug_app_debuggable",
        "emu_build", "emu_files",
        "env_dev_options", "env_adb", "env_vpn", "env_in_call", "env_external_display", "env_remote_access_a11y",
    )

    @Test
    fun cleanPhoneReportsNothing() {
        val report = collect()
        assertEquals(1, report.getInt("v"))
        boolKeys.forEach { assertFalse(it, report.getBoolean(it)) }
        assertEquals(0, report.getInt("env_a11y_third_party"))
        assertEquals(0, report.getJSONArray("env_remote_access_apps").length())
        assertEquals("com.android.vending", report.getString("app_installer"))
    }

    @Test
    fun reportHasExactlyTheServerSchema() {
        val expected = boolKeys.toSet() + setOf(
            "v", "env_a11y_third_party", "env_remote_access_apps", "app_installer", "app_signature_sha256",
            "os_security_patch", "os_release",
        )
        assertEquals(expected, collect().keySet())
    }

    @Test fun suOnPath() = assertTrue(collect { files += "/system/xbin/su" }.getBoolean("root_su"))
    @Test fun suInPathEnv() = assertTrue(collect { files += "/product/bin/su" }.getBoolean("root_su"))
    @Test fun magiskFiles() = assertTrue(collect { files += "/data/adb/modules" }.getBoolean("root_magisk"))
    @Test fun magiskMounts() = assertTrue(
        collect { texts["/proc/self/mounts"] = "magisk /system/bin tmpfs ro 0 0" }.getBoolean("root_magisk"),
    )
    @Test fun rootManagerApp() = assertTrue(collect { packages += "me.weishu.kernelsu" }.getBoolean("root_apps"))
    @Test fun testKeys() = assertTrue(collect { buildInfo = PIXEL.copy(tags = "test-keys") }.getBoolean("root_test_keys"))

    @Test
    fun systemRw() {
        assertTrue(collect { texts["/proc/mounts"] = "/dev/block/dm-0 /system ext4 rw,seclabel 0 0" }.getBoolean("root_system_rw"))
        assertFalse(collect { texts["/proc/mounts"] = "/dev/block/dm-0 /system ext4 ro,seclabel 0 0" }.getBoolean("root_system_rw"))
        assertFalse(collect { texts["/proc/mounts"] = "tmpfs /system_ext tmpfs rw 0 0" }.getBoolean("root_system_rw"))
    }

    @Test fun fridaInMaps() = assertTrue(
        collect { texts["/proc/self/maps"] = "7f00 r-xp 00 00:00 0 /data/local/tmp/frida-agent-64.so" }.getBoolean("hook_frida"),
    )
    @Test fun fridaPort() = assertTrue(collect { openPorts += 27042 }.getBoolean("hook_frida_port"))
    @Test fun xposedClass() = assertTrue(collect { classes += "de.robv.android.xposed.XposedBridge" }.getBoolean("hook_xposed"))
    @Test fun lsposedMaps() = assertTrue(collect { texts["/proc/self/maps"] = "/apex/liblspd.so" }.getBoolean("hook_xposed"))
    @Test fun xposedStack() = assertTrue(
        collect { stack = listOf("de.robv.android.xposed.XposedBridge.main") }.getBoolean("hook_xposed"),
    )
    @Test fun zygisk() = assertTrue(collect { texts["/proc/self/maps"] = "/memfd:zygisk-module" }.getBoolean("hook_zygisk"))

    @Test fun debuggerAttached() = assertTrue(collect { debugger = true }.getBoolean("debug_attached"))
    @Test fun appDebuggable() = assertTrue(collect { debuggable = true }.getBoolean("debug_app_debuggable"))

    @Test
    fun tracerPid() {
        assertTrue(collect { texts["/proc/self/status"] = "Name:\tbank\nTracerPid:\t4242\n" }.getBoolean("debug_traced"))
        assertFalse(collect { texts["/proc/self/status"] = "Name:\tbank\nTracerPid:\t0\n" }.getBoolean("debug_traced"))
    }

    @Test
    fun emulatorBuilds() {
        val emulators = listOf(
            PIXEL.copy(fingerprint = "google/sdk_gphone64_x86_64/emu64x:14/UE1A/1:userdebug/dev-keys", hardware = "ranchu",
                product = "sdk_gphone64_x86_64", model = "sdk_gphone64_x86_64"),
            PIXEL.copy(fingerprint = "generic/vbox86p/vbox86p:9/PI/1:userdebug/test-keys", hardware = "vbox86",
                manufacturer = "Genymotion"),
            PIXEL.copy(model = "Android SDK built for x86"),
        )
        emulators.forEach { b -> assertTrue(b.toString(), collect { buildInfo = b }.getBoolean("emu_build")) }
    }

    @Test fun emulatorFiles() = assertTrue(collect { files += "/dev/qemu_pipe" }.getBoolean("emu_files"))

    @Test
    fun realDevicesAreNotEmulators() {
        val real = listOf(
            PIXEL,
            BuildInfo("release-keys", "samsung/e3qxeea/e3q:14/UP1A/S928BXXU1AXB5:user/release-keys",
                "qcom", "e3qxeea", "SM-S928B", "samsung", "samsung", "e3q"),
            BuildInfo("release-keys", "Xiaomi/fuxi_eea/fuxi:14/UKQ1/V816.0.5.0:user/release-keys",
                "qcom", "fuxi_eea", "23127PN0CG", "Xiaomi", "Xiaomi", "fuxi"),
        )
        real.forEach { b -> assertFalse(b.toString(), DeviceSignals.looksLikeEmulator(b)) }
    }

    @Test
    fun environment() {
        val report = collect {
            settings[DeviceSignals.DEVELOPMENT_SETTINGS_ENABLED] = 1
            settings[DeviceSignals.ADB_ENABLED] = 1
            vpn = true
            inCall = true
            externalDisplay = true
        }
        listOf("env_dev_options", "env_adb", "env_vpn", "env_in_call", "env_external_display")
            .forEach { assertTrue(it, report.getBoolean(it)) }
    }

    @Test
    fun accessibilityAndRemoteAccess() {
        val report = collect {
            packages += "com.anydesk.anydeskandroid"
            a11y = listOf(
                AccessibilityServiceRef("com.google.android.marvin.talkback", isSystemApp = true),
                AccessibilityServiceRef("com.anydesk.anydeskandroid", isSystemApp = false),
                AccessibilityServiceRef("com.some.autoclicker", isSystemApp = false),
                AccessibilityServiceRef("com.some.autoclicker", isSystemApp = false),
            )
        }
        assertEquals(2, report.getInt("env_a11y_third_party"))
        assertTrue(report.getBoolean("env_remote_access_a11y"))
        assertEquals("anydesk", report.getJSONArray("env_remote_access_apps").getString(0))
    }

    @Test
    fun reportsOsFactsForAttestationCrossCheck() {
        val report = collect()
        assertEquals("2026-09-05", report.getString("os_security_patch"))
        assertEquals("16", report.getString("os_release"))
        assertTrue(collect { buildInfo = PIXEL.copy(securityPatch = "", release = "") }.isNull("os_release"))
    }

    @Test
    fun sideloadedAndUnknownSignature() {
        val report = collect { installer = null; signature = null }
        assertTrue(report.isNull("app_installer"))
        assertTrue(report.isNull("app_signature_sha256"))
    }

    @Test
    fun throwingProbeNeverCrashesCollection() {
        val hostile = object : FakeProbe() {
            override fun readText(path: String): String = throw SecurityException("denied")
            override fun isPackageInstalled(packageName: String): Boolean = throw IllegalStateException()
            override fun canConnectLoopback(port: Int): Boolean = throw RuntimeException()
            override fun build(): BuildInfo = throw RuntimeException()
            override fun enabledAccessibilityServices(): List<AccessibilityServiceRef> = throw RuntimeException()
        }
        val report = DeviceSignals(hostile).collect()
        assertFalse(report.getBoolean("hook_frida"))
        assertFalse(report.getBoolean("emu_build"))
        assertEquals(0, report.getInt("env_a11y_third_party"))
    }

    /** Writes a fully-detected report for the cross-language check against the Python parser. */
    @Test
    fun writeSampleForServerCompatibilityCheck() {
        val report = collect {
            files += setOf("/system/xbin/su", "/data/adb/modules", "/dev/qemu_pipe")
            packages += setOf("com.topjohnwu.magisk", "com.carriez.flutter_hbb")
            texts["/proc/self/maps"] = "frida-agent zygisk liblspd"
            openPorts += 27042
            installer = "com.other.store"
            a11y = listOf(AccessibilityServiceRef("com.carriez.flutter_hbb", false))
        }
        File("build/signals-sample.json").apply { parentFile?.mkdirs() }.writeText(report.toString())
    }
}
