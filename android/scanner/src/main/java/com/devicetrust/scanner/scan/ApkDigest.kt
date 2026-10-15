package com.devicetrust.scanner.scan

import android.content.Context
import java.io.File
import java.security.MessageDigest

/** Run 30: SHA-256 of the installed base APK, to tie lab observations to the exact candidate build. */
object ApkDigest {
    fun of(context: Context): String? = runCatching {
        sha256(File(context.applicationInfo.sourceDir))
    }.getOrNull()

    fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                digest.update(buffer, 0, n)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
