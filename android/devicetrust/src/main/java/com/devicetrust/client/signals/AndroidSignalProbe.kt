package com.devicetrust.client.signals

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.media.AudioManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest

/** Real [SignalProbe] backed by Android APIs. Every method swallows errors. */
class AndroidSignalProbe(context: Context) : SignalProbe {
    private val app = context.applicationContext
    private val pm: PackageManager = app.packageManager

    override fun fileExists(path: String): Boolean = runCatching { File(path).exists() }.getOrDefault(false)

    override fun readText(path: String): String? = runCatching {
        File(path).inputStream().use { input ->
            val buf = ByteArray(MAX_READ)
            var total = 0
            while (total < MAX_READ) {
                val n = input.read(buf, total, MAX_READ - total)
                if (n < 0) break
                total += n
            }
            String(buf, 0, total, Charsets.UTF_8)
        }
    }.getOrNull()

    override fun pathDirectories(): List<String> =
        System.getenv("PATH").orEmpty().split(':').filter(String::isNotBlank)

    override fun build(): BuildInfo = BuildInfo(
        tags = Build.TAGS.orEmpty(),
        fingerprint = Build.FINGERPRINT.orEmpty(),
        hardware = Build.HARDWARE.orEmpty(),
        product = Build.PRODUCT.orEmpty(),
        model = Build.MODEL.orEmpty(),
        manufacturer = Build.MANUFACTURER.orEmpty(),
        brand = Build.BRAND.orEmpty(),
        device = Build.DEVICE.orEmpty(),
    )

    override fun isPackageInstalled(packageName: String): Boolean = runCatching {
        packageInfo(packageName, 0)
        true
    }.getOrDefault(false)

    override fun globalSettingInt(name: String): Int? =
        runCatching { Settings.Global.getInt(app.contentResolver, name) }.getOrNull()

    override fun enabledAccessibilityServices(): List<AccessibilityServiceRef> = runCatching {
        app.getSystemService(AccessibilityManager::class.java)
            .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .mapNotNull { info ->
                val service = info.resolveInfo?.serviceInfo ?: return@mapNotNull null
                val flags = service.applicationInfo?.flags ?: 0
                AccessibilityServiceRef(
                    packageName = service.packageName,
                    isSystemApp = flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0,
                )
            }
    }.getOrDefault(emptyList())

    override fun isDebuggerConnected(): Boolean = Debug.isDebuggerConnected() || Debug.waitingForDebugger()

    override fun isAppDebuggable(): Boolean = app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    override fun installerPackage(): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(app.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(app.packageName)
        }
    }.getOrNull()

    override fun signingCertSha256(): String? = runCatching {
        val cert = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = packageInfo(app.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
                ?: return@runCatching null
            if (info.hasMultipleSigners()) info.apkContentsSigners.first() else info.signingCertificateHistory.last()
        } else {
            @Suppress("DEPRECATION")
            packageInfo(app.packageName, PackageManager.GET_SIGNATURES).signatures?.first()
        } ?: return@runCatching null
        MessageDigest.getInstance("SHA-256").digest(cert.toByteArray()).joinToString("") { "%02x".format(it) }
    }.getOrNull()

    override fun canConnectLoopback(port: Int): Boolean = runCatching {
        Socket().use { it.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), LOOPBACK_TIMEOUT_MS) }
        true
    }.getOrDefault(false)

    override fun classExists(name: String): Boolean = runCatching {
        Class.forName(name, false, ClassLoader.getSystemClassLoader())
        true
    }.getOrDefault(false)

    override fun currentStackTrace(): List<String> =
        Throwable().stackTrace.map { "${it.className}.${it.methodName}" }

    override fun isVpnActive(): Boolean = runCatching {
        val cm = app.getSystemService(ConnectivityManager::class.java)
        cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }.getOrDefault(false)

    override fun isInCall(): Boolean = runCatching {
        val mode = app.getSystemService(AudioManager::class.java).mode
        mode == AudioManager.MODE_IN_CALL || mode == AudioManager.MODE_IN_COMMUNICATION
    }.getOrDefault(false)

    override fun hasExternalDisplay(): Boolean = runCatching {
        val dm = app.getSystemService(DisplayManager::class.java)
        dm.getDisplays(DisplayManager.DISPLAY_CATEGORY_PRESENTATION).isNotEmpty() || dm.displays.size > 1
    }.getOrDefault(false)

    private fun packageInfo(name: String, flags: Int) =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(name, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(name, flags)
        }

    private companion object {
        const val MAX_READ = 512 * 1024
        const val LOOPBACK_TIMEOUT_MS = 150
    }
}
