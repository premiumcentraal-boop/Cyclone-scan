package com.devicetrust.scanner.scan

import android.content.Context
import com.devicetrust.scanner.attest.RevocationCopy

/**
 * The last live revocation list, kept in this app's own preferences. It is Google's public
 * list, so it holds no identifiers, and it is only used when a live download fails.
 */
class RevocationCache(context: Context) {
    private val prefs = context.getSharedPreferences("revocation_cache", Context.MODE_PRIVATE)

    fun load(): RevocationCopy? = try {
        val serials = prefs.getString(KEY_SERIALS, null) ?: return null
        val savedAt = prefs.getLong(KEY_SAVED_AT, -1L)
        if (savedAt < 0) null else RevocationCopy(serials.split(',').filter { it.isNotEmpty() }.toSet(), savedAt)
    } catch (_: Exception) {
        null
    }

    fun save(serials: Set<String>, nowMs: Long) {
        prefs.edit().putString(KEY_SERIALS, serials.joinToString(",")).putLong(KEY_SAVED_AT, nowMs).apply()
    }

    private companion object {
        const val KEY_SERIALS = "serials"
        const val KEY_SAVED_AT = "saved_at_ms"
    }
}
