package com.devicetrust.client.signals

import org.json.JSONObject

enum class NativeState { DETECTED, NOT_DETECTED, UNAVAILABLE, UNSUPPORTED }
fun interface NativeProbe { fun collect(): Map<String, NativeState> }

/** One JNI entry point. Library-load errors never abort host collection. */
object JniNativeProbe : NativeProbe {
    private val loadFailure: Throwable? by lazy {
        runCatching { System.loadLibrary("dtnative") }.exceptionOrNull()
    }
    private external fun scanRaw(): String?

    /**
     * Why the last [collect] produced no native results (diagnostics only, Run 31): the
     * library-load or collection error class and message, or null when it completed.
     */
    @Volatile var lastError: String? = null
        private set

    override fun collect(): Map<String, NativeState> {
        loadFailure?.let {
            lastError = "native library not loaded: ${it.javaClass.simpleName}: ${it.message.orEmpty().take(160)}"
            return NativeSignals.CHECKS.associateWith { NativeState.UNSUPPORTED }
        }
        return runCatching {
            val raw = JSONObject(scanRaw() ?: error("native collector returned no report"))
            NativeSignals.CHECKS.associateWith { key ->
                val state = NativeState.valueOf(raw.getString("native_" + key + "_status"))
                require(raw.getBoolean("native_" + key) == (state == NativeState.DETECTED)) { "inconsistent result for $key" }
                state
            }
        }.onSuccess { lastError = null }
            .onFailure { lastError = "native collection failed: ${it.javaClass.simpleName}: ${it.message.orEmpty().take(160)}" }
            .getOrDefault(emptyMap())
    }
}

/** Keeps native evidence separate; comparisons use only stable, equivalent snapshots. */
object NativeSignals {
    val CHECKS = listOf("root_su", "root_magisk", "root_system_rw", "hook_frida",
        "hook_xposed", "hook_zygisk", "debug_traced", "selinux_permissive", "code_modified")

    data class Snapshot(val maps: String?, val tracer: Int?)
    fun snapshot(probe: SignalProbe): Snapshot {
        val maps = runCatching { probe.readText("/proc/self/maps") }.getOrNull()
        val status = runCatching { probe.readText("/proc/self/status") }.getOrNull()
        val tracer = status?.lineSequence()?.firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(':')?.trim()?.toIntOrNull()?.takeIf { it >= 0 }
        return Snapshot(maps, tracer)
    }

    fun enrich(report: JSONObject, probe: SignalProbe, native: NativeProbe) {
        val before = snapshot(probe)
        val results = runCatching { native.collect() }.getOrDefault(emptyMap())
        val after = snapshot(probe)
        append(report, results, before, after)
    }

    fun append(report: JSONObject, results: Map<String, NativeState>, before: Snapshot, after: Snapshot) {
        val comparisons = mutableListOf<Boolean>()
        for (key in CHECKS) {
            val state = results[key] ?: NativeState.UNAVAILABLE
            report.put("native_" + key, state == NativeState.DETECTED)
            report.put("native_" + key + "_status", state.name)
            val expected = when {
                before.maps != null && before.maps == after.maps -> {
                    val maps = before.maps.lowercase()
                    when (key) {
                        "hook_frida" -> listOf("frida", "gum-js-loop", "gadget").any { it in maps }
                        "hook_xposed" -> DeviceSignals.XPOSED_MAP_TOKENS.any { it in maps }
                        "hook_zygisk" -> "zygisk" in maps
                        else -> null
                    }
                }
                else -> null
            } ?: if (key == "debug_traced" && before.tracer != null && before.tracer == after.tracer)
                before.tracer > 0 else null
            val complete = state == NativeState.DETECTED || state == NativeState.NOT_DETECTED
            if (expected != null && complete) comparisons += expected != (state == NativeState.DETECTED)
            report.put("native_" + key + "_comparison",
                if (expected == null || !complete) "UNAVAILABLE"
                else if (expected != (state == NativeState.DETECTED)) "MISMATCH" else "MATCH")
            report.put("kotlin_" + key + "_comparison_status",
                if (expected == null) "UNAVAILABLE" else if (expected) "DETECTED" else "NOT_DETECTED")
        }
        val mismatch = comparisons.any { it }
        report.put("native_kotlin_mismatch", mismatch)
        report.put("native_kotlin_mismatch_status",
            if (mismatch) "DETECTED" else if (comparisons.isEmpty()) "UNAVAILABLE" else "NOT_DETECTED")
        report.put("native_collector_version", "2")
    }
}
