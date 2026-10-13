package com.devicetrust.client.signals

/**
 * Thin seam over everything the collectors read from the OS, so the
 * detection logic is plain Kotlin and unit-testable. Implementations must not
 * throw; return false/null/empty when something cannot be read.
 */
interface SignalProbe {
    fun fileExists(path: String): Boolean
    fun readText(path: String): String?
    fun pathDirectories(): List<String>
    fun build(): BuildInfo
    fun isPackageInstalled(packageName: String): Boolean
    fun globalSettingInt(name: String): Int?
    /** Enabled accessibility services, with whether their app is a system app. */
    fun enabledAccessibilityServices(): List<AccessibilityServiceRef>
    fun isDebuggerConnected(): Boolean
    fun isAppDebuggable(): Boolean
    fun installerPackage(): String?
    /** SHA-256 (lowercase hex) of the app's current signing certificate. */
    fun signingCertSha256(): String?
    fun canConnectLoopback(port: Int): Boolean
    fun classExists(name: String): Boolean
    fun currentStackTrace(): List<String>
    fun isVpnActive(): Boolean
    fun isInCall(): Boolean
    fun hasExternalDisplay(): Boolean
}

data class BuildInfo(
    val tags: String,
    val fingerprint: String,
    val hardware: String,
    val product: String,
    val model: String,
    val manufacturer: String,
    val brand: String,
    val device: String,
    /** Build.VERSION.SECURITY_PATCH, e.g. "2026-09-05" (cross-checked with the attested patch). */
    val securityPatch: String = "",
    /** Build.VERSION.RELEASE, e.g. "16" (cross-checked with the attested OS version). */
    val release: String = "",
)

data class AccessibilityServiceRef(val packageName: String, val isSystemApp: Boolean)
