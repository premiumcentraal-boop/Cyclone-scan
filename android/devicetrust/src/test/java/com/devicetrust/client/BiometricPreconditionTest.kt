package com.devicetrust.client

import org.junit.Assert.assertTrue
import org.junit.Test

class BiometricPreconditionTest {
    // Values of BiometricManager.canAuthenticate: SUCCESS 0, ERROR_NONE_ENROLLED 11, ERROR_NO_HARDWARE 12.

    @Test
    fun noScreenLockIsNamedFirst() {
        // Enrolling a biometric needs a screen lock, so with no lock the lock is the cause.
        assertTrue(BiometricPrecondition.explain(11, deviceSecure = false).startsWith("no screen lock"))
        assertTrue(BiometricPrecondition.explain(0, deviceSecure = false).startsWith("no screen lock"))
    }

    @Test
    fun noEnrolledBiometricIsItsOwnMessage() {
        val message = BiometricPrecondition.explain(11, deviceSecure = true)
        assertTrue(message.contains("no strong fingerprint or face is enrolled"))
        assertTrue(!message.contains("screen lock"))
    }

    @Test
    fun noSensorIsItsOwnMessage() {
        assertTrue(BiometricPrecondition.explain(12, deviceSecure = true).contains("no strong biometric sensor"))
    }

    @Test
    fun enrolledButKeyFailedIsReportedAsSuch() {
        assertTrue(BiometricPrecondition.explain(0, deviceSecure = true).contains("could not be created"))
    }
}
