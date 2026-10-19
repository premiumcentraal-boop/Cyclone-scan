package com.devicetrust.client.signals

import org.junit.Assert.assertEquals
import org.junit.Test

class ScopedHookTest {
    @Test
    fun notFoundInThisProcessIsPartialCoverageNotAClearResult() {
        val r = scopedToThisProcess(CheckResult.NOT_DETECTED)
        assertEquals(CheckState.UNAVAILABLE, r.state)
        assertEquals(CheckReason.SCOPE_LIMITED, r.reason)
        assertEquals(false, r.completed)
    }

    @Test
    fun aDetectionInThisProcessIsKept() {
        assertEquals(CheckResult.DETECTED, scopedToThisProcess(CheckResult.DETECTED))
    }

    @Test
    fun anUnavailableResultIsNotChanged() {
        val unavailable = CheckResult.unavailable(CheckReason.ACCESS_DENIED)
        assertEquals(unavailable, scopedToThisProcess(unavailable))
    }
}
