package com.devicetrust.client

import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.security.Signature
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Unlocks a confirm-key [Signature] by authenticating the user. */
fun interface UserAuthenticator {
    /** Returns the same [Signature], now usable for exactly one `sign()`. */
    suspend fun authenticate(signature: Signature): Signature
}

/** The user cancelled or failed biometric authentication. */
class UserAuthenticationException(val errorCode: Int, message: String) : DeviceTrustException(message)

/**
 * Shows BiometricPrompt bound to the confirm key through a CryptoObject, so
 * the secure hardware itself enforces that this signature was approved by a
 * strong biometric. Show the action details (payee, amount) in [subtitle] or
 * [description]: the user is approving what they see.
 */
class BiometricPromptAuthenticator(
    private val activity: FragmentActivity,
    private val title: String,
    private val subtitle: String? = null,
    private val description: String? = null,
    private val negativeButtonText: String = "Cancel",
) : UserAuthenticator {
    override suspend fun authenticate(signature: Signature): Signature = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { cont ->
            val prompt = BiometricPrompt(
                activity,
                ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val unlocked = result.cryptoObject?.signature
                        if (unlocked == null) {
                            cont.resumeWithException(DeviceTrustException("biometric result had no signature"))
                        } else {
                            cont.resume(unlocked)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (cont.isActive) {
                            cont.resumeWithException(UserAuthenticationException(errorCode, errString.toString()))
                        }
                    }
                    // onAuthenticationFailed (one bad attempt) keeps the prompt open.
                },
            )
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .apply {
                    subtitle?.let { setSubtitle(it) }
                    description?.let { setDescription(it) }
                }
                .setNegativeButtonText(negativeButtonText)
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setConfirmationRequired(true)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
            cont.invokeOnCancellation { prompt.cancelAuthentication() }
        }
    }
}
