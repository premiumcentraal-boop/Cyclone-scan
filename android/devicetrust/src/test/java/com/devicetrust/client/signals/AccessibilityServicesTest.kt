package com.devicetrust.client.signals

import org.junit.Assert.assertEquals
import org.junit.Test

class AccessibilityServicesTest {
    @Test
    fun readsPackageNamesFromComponentNames() {
        assertEquals(
            setOf("com.a", "com.b"),
            AccessibilityServices.packagesFromSecureSetting("com.a/.S:com.b/com.b.T"),
        )
    }

    @Test
    fun emptyAndUnsetSettingsGiveNothing() {
        assertEquals(emptySet<String>(), AccessibilityServices.packagesFromSecureSetting(null))
        assertEquals(emptySet<String>(), AccessibilityServices.packagesFromSecureSetting(""))
    }

    @Test
    fun servicesOnlyTheSecureSettingNamesAreStillCounted() {
        // The race behind a false "none enabled": the manager list is empty for a moment,
        // but the secure setting still names the services.
        assertEquals(
            setOf("com.a", "com.b"),
            AccessibilityServices.union(emptyList(), "com.a/.S:com.b/.T"),
        )
    }

    @Test
    fun aServiceNamedByBothSourcesIsCountedOnce() {
        assertEquals(setOf("com.a"), AccessibilityServices.union(listOf("com.a"), "com.a/.S"))
    }
}
