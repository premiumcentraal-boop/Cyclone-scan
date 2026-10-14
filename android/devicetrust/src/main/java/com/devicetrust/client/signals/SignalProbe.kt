package com.devicetrust.client.signals

/**
 * Thin seam over everything the collectors read from the OS, so the
 * detection logic is plain Kotlin and unit-testable.
 *
 * Coverage contract (Run 14): a method returns false/null/empty only when the
 * query completed and that is the answer. When the OS refuses or fails a query
 * the implementation may throw; [DeviceSignals] records the throw as
 * UNAVAILABLE (or UNSUPPORTED) instead of a clean "not detected".
 * [readText] keeps returning null for any unreadable file; [readTextResult]
 * and [pathState] add the reason.
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

    /** Whether a fixed path exists, separating "absent" from "could not look". */
    fun pathState(path: String): PathState = if (fileExists(path)) PathState.PRESENT else PathState.ABSENT

    /** Like [readText], but says why a read did not complete. */
    fun readTextResult(path: String): TextRead =
        readText(path)?.let { TextRead.Ok(it) } ?: TextRead.Failed(CheckReason.READ_ERROR)
}

enum class PathState { PRESENT, ABSENT, INACCESSIBLE }

sealed interface TextRead {
    data class Ok(val text: String) : TextRead
    data class Failed(val reason: CheckReason) : TextRead
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
