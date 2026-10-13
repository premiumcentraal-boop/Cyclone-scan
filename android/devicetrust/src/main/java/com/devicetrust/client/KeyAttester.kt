package com.devicetrust.client

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** A hardware-backed key plus the attestation chain that proves where it lives. */
class AttestedKey(
    val alias: String,
    /** DER certificates, leaf first. */
    val chain: List<ByteArray>,
    /** DER SubjectPublicKeyInfo of the attested key. */
    val publicKeySpki: ByteArray,
    val strongBox: Boolean,
)

interface KeyAttester {
    /** Device-binding key: signs without user interaction. */
    fun generate(alias: String, challenge: ByteArray): AttestedKey

    /**
     * Confirm key: every signature needs a fresh strong-biometric authentication,
     * and the key is destroyed if biometrics change. Returns null when the
     * device cannot create one (no strong biometric enrolled, no secure lock screen).
     */
    fun generateConfirmKey(alias: String, challenge: ByteArray): AttestedKey?

    /**
     * A [Signature] initialised for signing with [alias]. For a confirm key it
     * still has to be unlocked through BiometricPrompt before `sign()`.
     *
     * @throws ConfirmKeyInvalidatedException if the key was invalidated.
     * @throws NotEnrolledException if the key no longer exists.
     */
    fun signer(alias: String): Signature

    fun delete(alias: String)
}

/**
 * Generates non-exportable EC P-256 keys in AndroidKeyStore with the server
 * challenge in their attestation certificates.
 *
 * Tries StrongBox first, then the TEE; asks for device-property attestation on
 * Android 12+ and falls back without it on devices that cannot provide it. The
 * server decides whether the resulting security level is acceptable.
 */
class AndroidKeyAttester(context: Context) : KeyAttester {
    private val hasStrongBox =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    override fun generate(alias: String, challenge: ByteArray): AttestedKey =
        generateWithFallbacks(alias, challenge, userAuth = false)
            ?: throw DeviceTrustException("no hardware-backed key could be generated", lastFailure)

    override fun generateConfirmKey(alias: String, challenge: ByteArray): AttestedKey? =
        generateWithFallbacks(alias, challenge, userAuth = true)

    override fun signer(alias: String): Signature {
        val key = keyStore().getKey(alias, null) as? PrivateKey ?: throw NotEnrolledException()
        return try {
            Signature.getInstance(SIGNATURE_ALGORITHM).apply { initSign(key) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw ConfirmKeyInvalidatedException(e)
        }
    }

    override fun delete(alias: String) {
        runCatching { keyStore().deleteEntry(alias) }
    }

    private data class Attempt(val strongBox: Boolean, val deviceProperties: Boolean)

    @Volatile private var lastFailure: Exception? = null

    private fun generateWithFallbacks(alias: String, challenge: ByteArray, userAuth: Boolean): AttestedKey? {
        val attempts = buildList {
            if (hasStrongBox) {
                add(Attempt(strongBox = true, deviceProperties = true))
                add(Attempt(strongBox = true, deviceProperties = false))
            }
            add(Attempt(strongBox = false, deviceProperties = true))
            add(Attempt(strongBox = false, deviceProperties = false))
        }.filter { !it.deviceProperties || Build.VERSION.SDK_INT >= Build.VERSION_CODES.S }

        for (attempt in attempts) {
            try {
                return generateOnce(alias, challenge, attempt, userAuth)
            } catch (e: Exception) {
                lastFailure = e
                delete(alias)
                // A user-auth key fails outright when no strong biometric is enrolled;
                // every other failure is worth retrying with fewer features.
                if (!userAuth && !isRecoverable(e)) throw DeviceTrustException("key generation failed", e)
            }
        }
        return null
    }

    private fun generateOnce(alias: String, challenge: ByteArray, attempt: Attempt, userAuth: Boolean): AttestedKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .apply {
                if (attempt.strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
                if (attempt.deviceProperties && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    setDevicePropertiesAttestationIncluded(true)
                }
                if (userAuth) {
                    setUserAuthenticationRequired(true)
                    // Authenticate for every single signature with a strong biometric.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    } else {
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(-1)
                    }
                    setInvalidatedByBiometricEnrollment(true)
                }
            }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
            initialize(spec)
            generateKeyPair()
        }
        val chain = keyStore().getCertificateChain(alias)
            ?: throw DeviceTrustException("keystore returned no attestation chain")
        if (chain.size < 2) throw DeviceTrustException("attestation chain too short")
        return AttestedKey(
            alias = alias,
            chain = chain.map { it.encoded },
            publicKeySpki = chain[0].publicKey.encoded,
            strongBox = attempt.strongBox,
        )
    }

    private fun isRecoverable(e: Exception): Boolean =
        (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && e is StrongBoxUnavailableException) ||
            e is ProviderException ||
            e.cause is ProviderException

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }
}
