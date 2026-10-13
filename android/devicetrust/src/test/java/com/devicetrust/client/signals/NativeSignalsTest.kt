package com.devicetrust.client.signals

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class NativeSignalsTest {
    private val clean = NativeSignals.CHECKS.associateWith { NativeState.NOT_DETECTED }
    private val stable = NativeSignals.Snapshot("", 0)

    @Test fun agreementAndUnavailableAreDifferent() {
        val r = JSONObject()
        NativeSignals.append(r, clean, stable, stable)
        assertFalse(r.getBoolean("native_kotlin_mismatch"))
        assertEquals("NOT_DETECTED", r.getString("native_kotlin_mismatch_status"))
        assertEquals("MATCH", r.getString("native_hook_frida_comparison"))
        assertEquals("UNAVAILABLE", r.getString("native_root_su_comparison"))
        NativeSignals.append(r, emptyMap(), stable, stable)
        assertEquals("UNAVAILABLE", r.getString("native_kotlin_mismatch_status"))
    }

    @Test fun eachComparableDisagreementIsDetected() {
        listOf("hook_frida", "hook_xposed", "hook_zygisk", "debug_traced").forEach { key ->
            val r = JSONObject()
            NativeSignals.append(r, clean + (key to NativeState.DETECTED), stable, stable)
            assertTrue(key, r.getBoolean("native_kotlin_mismatch"))
            assertEquals("MISMATCH", r.getString("native_" + key + "_comparison"))
        }
    }

    @Test fun positiveKotlinAndNegativeNativeIsAlsoMismatch() {
        val r = JSONObject()
        val s = NativeSignals.Snapshot("frida liblspd zygisk", 25)
        NativeSignals.append(r, clean, s, s)
        assertTrue(r.getBoolean("native_kotlin_mismatch"))
        assertEquals("DETECTED", r.getString("kotlin_debug_traced_comparison_status"))
    }

    @Test fun unavailableAndChangingSnapshotsNeverCreateMismatch() {
        val r = JSONObject()
        val hit = clean.mapValues { NativeState.DETECTED }
        NativeSignals.append(r, hit, NativeSignals.Snapshot("frida", 2), stable)
        assertFalse(r.getBoolean("native_kotlin_mismatch"))
        assertEquals("UNAVAILABLE", r.getString("native_kotlin_mismatch_status"))
        NativeSignals.append(r, clean.mapValues { NativeState.UNSUPPORTED }, stable, stable)
        assertFalse(r.getBoolean("native_kotlin_mismatch"))
    }

    @Test fun javaOnlyXposedAndPortChecksAreNotCompared() {
        val r = JSONObject().put("hook_xposed", true).put("hook_frida_port", true)
        NativeSignals.append(r, clean, stable, stable)
        assertFalse(r.getBoolean("native_kotlin_mismatch"))
    }

    @Test fun nativeErrorsNeverCrashOrEraseKotlinEvidence() {
        val r = DeviceSignals(FakeProbe(), NativeProbe { throw IllegalStateException("native failed") }).collect()
        assertEquals(1, r.getInt("v"))
        assertEquals("UNAVAILABLE", r.getString("native_root_su_status"))
        assertFalse(r.getBoolean("native_kotlin_mismatch"))
    }
}
