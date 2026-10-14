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
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.view.accessibility.AccessibilityManager
import java.io.File
import java.io.FileNotFoundException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest

/**
 * Real [SignalProbe] backed by Android APIs. A completed query returns its
 * answer; a refused or failed query throws (or reports INACCESSIBLE / a
 * [TextRead.Failed] reason) so the collector records UNAVAILABLE rather than
 * "not detected". See the coverage contract on [SignalProbe].
 */
class AndroidSignalProbe(context: Context) : SignalProbe {
    private val app = context.applicationContext
    private val pm: PackageManager = app.packageManager

    override fun fileExists(path: String): Boolean = pathState(path) == PathState.PRESENT

    /** stat(2) separates a missing path (ENOENT/ENOTDIR) from one the sandbox will not let us see. */
    override fun pathState(path: String): PathState = try {
        Os.stat(path)
        PathState.PRESENT
    } catch (e: ErrnoException) {
        if (e.errno == OsConstants.ENOENT || e.errno == OsConstants.ENOTDIR) PathState.ABSENT else PathState.INACCESSIBLE
    } catch (_: Exception) {
        PathState.INACCESSIBLE
    }

    override fun readText(path: String): String? = (readTextResult(path) as? TextRead.Ok)?.text

    override fun readTextResult(path: String): TextRead = try {
        File(path).inputStream().use { input ->
            val buf = ByteArray(MAX_READ)
            var total = 0
            while (total < MAX_READ) {
                val n = input.read(buf, total, MAX_READ - total)
                if (n < 0) break
                total += n
            }
            when {
                total == MAX_READ && input.read() != -1 -> TextRead.Failed(CheckReason.TOO_LARGE)
                (0 until total).any { buf[it] == 0.toByte() } -> TextRead.Failed(CheckReason.MALFORMED)
                else -> TextRead.Ok(String(buf, 0, total, Charsets.UTF_8))
            }
        }
    } catch (e: FileNotFoundException) {
        val errno = (e.cause as? ErrnoException)?.errno
        TextRead.Failed(
            if (errno == OsConstants.EACCES || errno == OsConstants.EPERM || e.message.orEmpty().contains("Permission denied"))
                CheckReason.ACCESS_DENIED else CheckReason.READ_ERROR,
        )
    } catch (_: SecurityException) {
        TextRead.Failed(CheckReason.ACCESS_DENIED)
    } catch (_: Exception) {
        TextRead.Failed(CheckReason.READ_ERROR)
    }

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
        securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty(),
        release = Build.VERSION.RELEASE.orEmpty(),
    )

    /** Visible because every queried package is declared in the manifest's <queries>. */
    override fun isPackageInstalled(packageName: String): Boolean = try {
        packageInfo(packageName, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    /** An unset setting has its platform default, which is 0 (off) for both settings we read. */
    override fun globalSettingInt(name: String): Int? = try {
        Settings.Global.getInt(app.contentResolver, name)
    } catch (_: Settings.SettingNotFoundException) {
        0
    }

    override fun enabledAccessibilityServices(): List<AccessibilityServiceRef> =
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

    override fun isDebuggerConnected(): Boolean = Debug.isDebuggerConnected() || Debug.waitingForDebugger()

    override fun isAppDebuggable(): Boolean = app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    override fun installerPackage(): String? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(app.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(app.packageName)
        }

    override fun signingCertSha256(): String? {
        val cert = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = packageInfo(app.packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
                ?: return null
            if (info.hasMultipleSigners()) info.apkContentsSigners.first() else info.signingCertificateHistory.last()
        } else {
            @Suppress("DEPRECATION")
            packageInfo(app.packageName, PackageManager.GET_SIGNATURES).signatures?.first()
        } ?: return null
        return MessageDigest.getInstance("SHA-256").digest(cert.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    /** Refused = closed port (completed). Timeouts and permission errors propagate as "could not verify". */
    override fun canConnectLoopback(port: Int): Boolean = try {
        Socket().use { it.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), LOOPBACK_TIMEOUT_MS) }
        true
    } catch (_: ConnectException) {
        false
    }

    override fun classExists(name: String): Boolean = try {
        Class.forName(name, false, ClassLoader.getSystemClassLoader())
        true
    } catch (_: ClassNotFoundException) {
        false
    }

    override fun currentStackTrace(): List<String> =
        Throwable().stackTrace.map { "${it.className}.${it.methodName}" }

    override fun isVpnActive(): Boolean {
        val cm = app.getSystemService(ConnectivityManager::class.java)
        return cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    override fun isInCall(): Boolean {
        val mode = app.getSystemService(AudioManager::class.java).mode
        return mode == AudioManager.MODE_IN_CALL || mode == AudioManager.MODE_IN_COMMUNICATION
    }

    override fun hasExternalDisplay(): Boolean {
        val dm = app.getSystemService(DisplayManager::class.java)
        return dm.getDisplays(DisplayManager.DISPLAY_CATEGORY_PRESENTATION).isNotEmpty() || dm.displays.size > 1
    }

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
