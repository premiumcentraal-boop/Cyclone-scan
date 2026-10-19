package com.devicetrust.scanner.ui

/**
 * The Server tab's address. The first versions pre-filled a placeholder LAN address that most
 * computers do not have; a stored copy of that placeholder is treated as empty.
 */
object ServerUrl {
    const val LEGACY_PLACEHOLDER = "http://192.168.1.10:8080"

    fun fromStored(value: String?): String = when (value) {
        null, LEGACY_PLACEHOLDER -> ""
        else -> value
    }
}
