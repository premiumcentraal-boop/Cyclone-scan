package com.devicetrust.client.signals

/**
 * Enabled accessibility services, from two sources. AccessibilityManager's list can be empty or
 * partial for a short time after a process starts, while the secure setting
 * `enabled_accessibility_services` still names the services. Counting both avoids a false
 * "none enabled" result.
 */
object AccessibilityServices {
    /** Package names from the colon-separated `package/class` values of the secure setting. */
    fun packagesFromSecureSetting(value: String?): Set<String> =
        value.orEmpty().split(':')
            .map { it.substringBefore('/').trim() }
            .filter { it.isNotEmpty() }
            .toSet()

    /** Packages named by either source, each counted once. */
    fun union(managerPackages: Collection<String>, secureValue: String?): Set<String> =
        managerPackages.toSet() + packagesFromSecureSetting(secureValue)
}
