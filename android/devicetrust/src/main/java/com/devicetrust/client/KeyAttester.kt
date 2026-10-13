package com.devicetrust.client

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.ProviderException
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
    fun generate(alias: String, challenge: ByteArray): AttestedKey
    fun delete(alias: String)
}

/**
 * Generates a non-exportable EC P-256 signing key in AndroidKeyStore with the
 * server challenge in its attestation certificate.
 *
 * Tries StrongBox first, then the TEE; asks for device-property attestation on
 * Android 12+ and falls back without it on devices that cannot provide it. The
 * server decides whether the resulting security level is acceptable.
 */
class AndroidKeyAttester(context: Context) : KeyAttester {
    private val hasStrongBox =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    override fun generate(alias: String, challenge: ByteArray): AttestedKey {
        val attempts = buildList {
            if (hasStrongBox) {
                add(Attempt(strongBox = true, deviceProperties = true))
                add(Attempt(strongBox = true, deviceProperties = false))
            }
            add(Attempt(strongBox = false, deviceProperties = true))
            add(Attempt(strongBox = false, deviceProperties = false))
        }.distinct().filter { !it.deviceProperties || Build.VERSION.SDK_INT >= Build.VERSION_CODES.S }

        var last: Exception? = null
        for (attempt in attempts) {
            try {
                return generateOnce(alias, challenge, attempt)
            } catch (e: Exception) {
                if (!isRecoverable(e)) throw DeviceTrustException("key generation failed", e)
                last = e
                delete(alias)
            }
        }
        throw DeviceTrustException("no hardware-backed key could be generated", last)
    }

    override fun delete(alias: String) {
        runCatching { keyStore().deleteEntry(alias) }
    }

    private data class Attempt(val strongBox: Boolean, val deviceProperties: Boolean)

    private fun generateOnce(alias: String, challenge: ByteArray, attempt: Attempt): AttestedKey {
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
    }
}
