package com.devicetrust.client

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID

/** Persists the current enrollment. The device ID is not a secret. */
interface EnrollmentStore {
    fun load(): Enrollment?
    fun save(enrollment: Enrollment)
    fun clear()
}

class SharedPreferencesEnrollmentStore(context: Context) : EnrollmentStore {
    private val prefs = context.applicationContext.getSharedPreferences("device_trust", Context.MODE_PRIVATE)

    override fun load(): Enrollment? {
        val id = prefs.getString(KEY_DEVICE_ID, null) ?: return null
        val alias = prefs.getString(KEY_ALIAS, null) ?: return null
        return Enrollment(id, alias)
    }

    override fun save(enrollment: Enrollment) {
        prefs.edit().putString(KEY_DEVICE_ID, enrollment.deviceId).putString(KEY_ALIAS, enrollment.keyAlias).apply()
    }

    override fun clear() {
        prefs.edit().clear().apply()
    }

    private companion object {
        const val KEY_DEVICE_ID = "device_id"
        const val KEY_ALIAS = "key_alias"
    }
}

/**
 * Phase 1 device enrollment.
 *
 * 1. fetch a single-use challenge from the server
 * 2. create a hardware key whose attestation certificate contains that challenge
 * 3. request a Play Integrity token bound to (challenge, attested public key)
 * 4. send everything to the server, which makes the decision
 *
 * The app never decides trust locally: it only reports [EnrollmentResult].
 * On ALLOW the new key becomes the device-binding key (used for per-action
 * signatures in Phase 2) and any previous binding key is deleted.
 */
class DeviceTrustClient(
    private val api: TrustApi,
    private val attester: KeyAttester,
    private val integrity: IntegrityTokenSource?,
    private val store: EnrollmentStore,
    private val deviceInfo: () -> DeviceInfo = DeviceInfo::current,
    private val newAlias: () -> String = { "device_trust_" + UUID.randomUUID() },
) {
    constructor(context: Context, api: TrustApi, cloudProjectNumber: Long?) : this(
        api = api,
        attester = AndroidKeyAttester(context),
        integrity = cloudProjectNumber?.let { PlayIntegrityTokenSource(context, it) },
        store = SharedPreferencesEnrollmentStore(context),
    )

    fun currentEnrollment(): Enrollment? = store.load()

    suspend fun enroll(): EnrollmentResult {
        val challenge = api.createChallenge()
        val alias = newAlias()
        val key = withContext(Dispatchers.Default) { attester.generate(alias, challenge.nonce) }
        var keep = false
        try {
            val token = integrity?.token(RequestHash.enrollment(challenge.nonce, key.publicKeySpki))
            val result = api.enroll(
                EnrollmentRequest(
                    challengeId = challenge.challengeId,
                    attestationChain = key.chain,
                    playIntegrityToken = token,
                    device = deviceInfo(),
                ),
            )
            if (result.decision == Decision.ALLOW && result.deviceId != null) {
                val previous = store.load()
                store.save(Enrollment(result.deviceId, alias))
                keep = true
                previous?.takeIf { it.keyAlias != alias }?.let { attester.delete(it.keyAlias) }
            }
            return result
        } finally {
            if (!keep) attester.delete(alias)
        }
    }
}
