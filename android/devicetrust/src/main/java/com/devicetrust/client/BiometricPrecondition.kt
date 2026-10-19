package com.devicetrust.client

import android.app.KeyguardManager
import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG

/**
 * Why a biometric-bound key cannot be created, in words a person can act on. These were one
 * message before ("no strong biometric enrolled or no screen lock set"), so a phone with no
 * screen lock looked like one with no fingerprint enrolled.
 */
object BiometricPrecondition {
    /** [canAuthenticate] is BiometricManager.canAuthenticate(BIOMETRIC_STRONG); [deviceSecure] is KeyguardManager.isDeviceSecure. */
    fun explain(canAuthenticate: Int, deviceSecure: Boolean): String = when {
        !deviceSecure -> "no screen lock is set; set a screen lock, then enroll a fingerprint or face"
        canAuthenticate == BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "this phone has no strong biometric sensor"
        canAuthenticate == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "no strong fingerprint or face is enrolled"
        canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS ->
            "a strong biometric is enrolled, but the biometric key could not be created"
        else -> "the biometric status is not available (code $canAuthenticate)"
    }

    fun explain(context: Context): String = explain(
        BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG),
        context.getSystemService(KeyguardManager::class.java).isDeviceSecure,
    )
}
