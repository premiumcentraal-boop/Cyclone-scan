package com.devicetrust.client.signals

/**
 * Typed coverage for the Kotlin checks (Run 14). Each boolean signal in the
 * report gets a sibling `<key>_status` and `<key>_reason`, so a denied or
 * failed read is never presented as a completed clean check. Booleans stay on
 * the wire for compatibility: `true` only ever means DETECTED.
 */
enum class CheckState { DETECTED, NOT_DETECTED, UNAVAILABLE, UNSUPPORTED }

/** Bounded reason vocabulary; mirrored in service/device_trust/signals.py. */
enum class CheckReason {
    /** The check ran to completion (DETECTED, NOT_DETECTED or COLLECTED). */
    COMPLETED,
    /** The OS or sandbox refused the read; normal for many paths on Android. */
    ACCESS_DENIED,
    /** Some inputs were readable and showed nothing; at least one was not. */
    PARTIAL_COVERAGE,
    READ_ERROR,
    MALFORMED,
    TOO_LARGE,
    API_ERROR,
    API_UNSUPPORTED,
}

/** State of a reported value (installer, signing digest, OS facts) rather than a detection. */
enum class ValueState { COLLECTED, UNAVAILABLE, UNSUPPORTED }

data class CheckResult(val state: CheckState, val reason: CheckReason) {
    val detected: Boolean get() = state == CheckState.DETECTED
    val completed: Boolean get() = state == CheckState.DETECTED || state == CheckState.NOT_DETECTED

    companion object {
        val DETECTED = CheckResult(CheckState.DETECTED, CheckReason.COMPLETED)
        val NOT_DETECTED = CheckResult(CheckState.NOT_DETECTED, CheckReason.COMPLETED)
        fun of(hit: Boolean) = if (hit) DETECTED else NOT_DETECTED
        fun unavailable(reason: CheckReason) = CheckResult(CheckState.UNAVAILABLE, reason)

        /** Classifies a throw from a probe call. */
        fun failure(t: Throwable): CheckResult = when (t) {
            is SecurityException -> unavailable(CheckReason.ACCESS_DENIED)
            is UnsupportedOperationException, is LinkageError -> CheckResult(CheckState.UNSUPPORTED, CheckReason.API_UNSUPPORTED)
            else -> unavailable(CheckReason.API_ERROR)
        }

        /**
         * Any-of combination, the same rule the native collector uses for path
         * artifacts: one hit is a detection; "not detected" needs every part
         * to have completed; otherwise the check could not be verified.
         */
        fun anyOf(parts: List<CheckResult>): CheckResult {
            if (parts.isEmpty()) return unavailable(CheckReason.API_ERROR)
            if (parts.any { it.detected }) return DETECTED
            if (parts.all { it.completed }) return NOT_DETECTED
            if (parts.all { it.state == CheckState.UNSUPPORTED }) return parts.first()
            val incomplete = parts.filterNot { it.completed }
            if (incomplete.size < parts.size) return unavailable(CheckReason.PARTIAL_COVERAGE)
            val reasons = incomplete.map { it.reason }.distinct()
            return unavailable(if (reasons.size == 1) reasons.single() else CheckReason.PARTIAL_COVERAGE)
        }
    }
}

/** Runs [block] and classifies a throw instead of collapsing it into "not detected". */
internal inline fun observe(block: () -> Boolean): CheckResult = try {
    CheckResult.of(block())
} catch (t: Throwable) {
    CheckResult.failure(t)
}

internal fun PathState.toResult(): CheckResult = when (this) {
    PathState.PRESENT -> CheckResult.DETECTED
    PathState.ABSENT -> CheckResult.NOT_DETECTED
    PathState.INACCESSIBLE -> CheckResult.unavailable(CheckReason.ACCESS_DENIED)
}
