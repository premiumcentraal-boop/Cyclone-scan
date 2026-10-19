package com.devicetrust.scanner.scan

import org.json.JSONObject

/**
 * Summary of the native-versus-Kotlin cross-check, from the `native_<check>_comparison` values of a
 * report. A comparison "matches" only when both sides answered; "disagrees" is a real mismatch; the
 * rest could not be compared (one side did not run, or the native layer gave no reason).
 */
object NativeKotlinSummary {
    data class Summary(val matched: Int, val disagree: Int, val notComparable: Int) {
        val status: String
            get() = when {
                disagree > 0 -> "MISMATCH_FOUND"
                matched > 0 -> "MATCHED"
                else -> "NOT_COMPARABLE"
            }

        fun detail(): String = "$matched matched · $disagree disagree · $notComparable not comparable"
    }

    fun of(values: Map<String, String>): Summary {
        var matched = 0
        var disagree = 0
        var notComparable = 0
        for ((key, value) in values) {
            if (!key.startsWith("native_") || !key.endsWith("_comparison")) continue
            when (value) {
                "MATCH" -> matched++
                "MISMATCH" -> disagree++
                else -> notComparable++
            }
        }
        return Summary(matched, disagree, notComparable)
    }

    fun of(signals: JSONObject): Summary =
        of(signals.keys().asSequence().associateWith { signals.optString(it) })
}
