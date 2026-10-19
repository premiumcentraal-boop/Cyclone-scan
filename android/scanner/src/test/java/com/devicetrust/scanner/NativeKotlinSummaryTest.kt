package com.devicetrust.scanner

import com.devicetrust.scanner.scan.NativeKotlinSummary
import org.junit.Assert.assertEquals
import org.junit.Test

class NativeKotlinSummaryTest {
    @Test
    fun countsMatchesDisagreementsAndUnavailableComparisons() {
        val s = NativeKotlinSummary.of(mapOf(
            "native_hook_frida_comparison" to "MATCH",
            "native_hook_xposed_comparison" to "MATCH",
            "native_root_magisk_comparison" to "UNAVAILABLE",
            "native_root_su_comparison" to "MISMATCH",
            "native_hook_zygisk_comparison" to "UNAVAILABLE",
            // Not a comparison, so not counted:
            "native_hook_frida_status" to "NOT_DETECTED",
        ))
        assertEquals(NativeKotlinSummary.Summary(matched = 2, disagree = 1, notComparable = 2), s)
        assertEquals("MISMATCH_FOUND", s.status)
        assertEquals("2 matched · 1 disagree · 2 not comparable", s.detail())
    }

    @Test
    fun allMatchedIsMatched() {
        val s = NativeKotlinSummary.of(mapOf("native_hook_frida_comparison" to "MATCH"))
        assertEquals("MATCHED", s.status)
    }

    @Test
    fun nothingComparableIsNotComparable() {
        val s = NativeKotlinSummary.of(mapOf("native_root_su_comparison" to "UNAVAILABLE"))
        assertEquals("NOT_COMPARABLE", s.status)
    }
}
