package com.devicetrust.client

import android.content.Context
import com.devicetrust.client.signals.AndroidSignalProbe
import com.devicetrust.client.signals.DeviceSignals
import com.devicetrust.client.signals.SignalCollector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
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
        return Enrollment(id, alias, prefs.getString(KEY_CONFIRM_ALIAS, null))
    }

    override fun save(enrollment: Enrollment) {
        prefs.edit()
            .putString(KEY_DEVICE_ID, enrollment.deviceId)
            .putString(KEY_ALIAS, enrollment.keyAlias)
            .putString(KEY_CONFIRM_ALIAS, enrollment.confirmKeyAlias)
            .apply()
    }

    override fun clear() {
        prefs.edit().clear().apply()
    }

    private companion object {
        const val KEY_DEVICE_ID = "device_id"
        const val KEY_ALIAS = "key_alias"
        const val KEY_CONFIRM_ALIAS = "confirm_key_alias"
    }
}

/**
 * Device trust client.
 *
 * **Enrollment** ([enroll]):
 * 1. fetch a single-use challenge from the server
 * 2. create a hardware device key (and, if strong biometrics are enrolled, a
 *    biometric-bound confirm key) whose attestation certificates contain that challenge
 * 3. request a Play Integrity token bound to (challenge, device public key)
 * 4. send everything to the server, which makes the decision
 *
 * **Signed actions** ([signAction]): for each sensitive action, fetch a
 * device-bound challenge and sign the action with the device key, or with the
 * confirm key after BiometricPrompt. Send the [SignedAction] to your backend
 * with the request; the backend verifies it with the trust service.
 *
 * The app never decides trust locally.
 */
class DeviceTrustClient(
    private val api: TrustApi,
    private val attester: KeyAttester,
    private val integrity: IntegrityTokenSource?,
    private val store: EnrollmentStore,
    private val deviceInfo: () -> DeviceInfo = DeviceInfo::current,
    private val newAlias: () -> String = { "device_trust_" + UUID.randomUUID() },
    private val clockMillis: () -> Long = System::currentTimeMillis,
    /** Client RASP signal collector (Phase 3); null sends no report. */
    private val signals: SignalCollector? = null,
) {
    constructor(context: Context, api: TrustApi, cloudProjectNumber: Long?) : this(
        api = api,
        attester = AndroidKeyAttester(context),
        integrity = cloudProjectNumber?.let { PlayIntegrityTokenSource(context, it) },
        store = SharedPreferencesEnrollmentStore(context),
        signals = DeviceSignals(AndroidSignalProbe(context)),
    )

    private suspend fun collectSignals() = signals?.let { c ->
        withContext(Dispatchers.IO) { runCatching { c.collect() }.getOrNull() }
    }

    fun currentEnrollment(): Enrollment? = store.load()

    /** True if the current enrollment has a biometric-bound confirm key. */
    fun hasConfirmKey(): Boolean = store.load()?.confirmKeyAlias != null

    /**
     * @param withConfirmKey also create a biometric-bound confirm key when the
     *   device supports one (needed for actions your policy marks high-risk).
     */
    suspend fun enroll(withConfirmKey: Boolean = true): EnrollmentResult {
        val challenge = api.createChallenge()
        val alias = newAlias()
        val confirmAlias = newAlias()
        var keep = false
        try {
            val key = withContext(Dispatchers.Default) { attester.generate(alias, challenge.nonce) }
            val confirm = if (withConfirmKey) {
                withContext(Dispatchers.Default) { attester.generateConfirmKey(confirmAlias, challenge.nonce) }
            } else {
                null
            }
            val token = integrity?.token(RequestHash.enrollment(challenge.nonce, key.publicKeySpki))
            val result = api.enroll(
                EnrollmentRequest(
                    challengeId = challenge.challengeId,
                    attestationChain = key.chain,
                    playIntegrityToken = token,
                    device = deviceInfo(),
                    confirmKeyChain = confirm?.chain,
                    signals = collectSignals(),
                ),
            )
            // STEP_UP enrollments are registered server-side too; the bank decides what to unlock.
            if (result.decision != Decision.BLOCK && result.deviceId != null) {
                val previous = store.load()
                store.save(Enrollment(result.deviceId, alias, confirm?.alias))
                keep = true
                previous?.let { old ->
                    if (old.keyAlias != alias) attester.delete(old.keyAlias)
                    old.confirmKeyAlias?.takeIf { it != confirm?.alias }?.let { attester.delete(it) }
                }
            }
            return result
        } finally {
            if (!keep) {
                attester.delete(alias)
                attester.delete(confirmAlias)
            }
        }
    }

    /**
     * Sign one sensitive action.
     *
     * @param type action type agreed with the server policy, e.g. "login", "payment".
     * @param params the exact action details the backend must execute (payee, amount, ...).
     * @param authenticator when given, sign with the confirm key after the user
     *   authenticates; required for actions the policy marks high-risk.
     * @throws NotEnrolledException if not enrolled (or the server no longer knows the device).
     * @throws ConfirmKeyInvalidatedException if biometrics changed; re-enroll.
     * @throws UserAuthenticationException if the user cancelled the prompt.
     */
    suspend fun signAction(
        type: String,
        params: JSONObject = JSONObject(),
        authenticator: UserAuthenticator? = null,
    ): SignedAction {
        val enrollment = store.load() ?: throw NotEnrolledException()
        val keyKind = if (authenticator != null) SigningKey.CONFIRM else SigningKey.DEVICE
        val alias = when (keyKind) {
            SigningKey.CONFIRM -> enrollment.confirmKeyAlias
                ?: throw DeviceTrustException("this enrollment has no confirm key")
            SigningKey.DEVICE -> enrollment.keyAlias
        }
        val challenge = api.createActionChallenge(enrollment.deviceId)
        val signedData = TrustJson.signedActionData(
            enrollment.deviceId, challenge, type, params, clockMillis(), collectSignals(),
        )

        var signer = withContext(Dispatchers.Default) { attester.signer(alias) }
        if (authenticator != null) signer = authenticator.authenticate(signer)
        val signature = withContext(Dispatchers.Default) {
            signer.update(signedData)
            signer.sign()
        }
        val token = integrity?.token(RequestHash.action(signedData))
        return SignedAction(enrollment.deviceId, challenge.challengeId, signedData, signature, keyKind, token)
    }

    /** Forget the local enrollment and delete its keys (e.g. on logout or after revocation). */
    fun reset() {
        store.load()?.let { e ->
            attester.delete(e.keyAlias)
            e.confirmKeyAlias?.let { attester.delete(it) }
        }
        store.clear()
    }
}
