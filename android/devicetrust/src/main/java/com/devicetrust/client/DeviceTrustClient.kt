package com.devicetrust.client

import android.content.Context
import com.devicetrust.client.signals.AndroidSignalProbe
import com.devicetrust.client.signals.DeviceSignals
import com.devicetrust.client.signals.SignalCollector
import kotlinx.coroutines.CancellationException
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
 * **Server-verified scan** ([verifiedScan], Run 17): the enrolled key signs a scan
 * transcript that carries fresh attestation from a short-lived key generated for the
 * server's nonce; the server returns a traceable verdict and history comparison.
 *
 * **Key rotation** ([rotateKeys], Run 17): the enrolled key authorises new keys; if the
 * enrolled key is lost, enroll again instead (a new device record).
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
    /** Disable only for a documented legacy server; production policy should require proofs. */
    private val bindEnrollmentEvidence: Boolean = true,
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
            val device = deviceInfo()
            val report = collectSignals()?.let { JSONObject(it.toString()) }
            val evidence = if (bindEnrollmentEvidence) EnrollmentProof.data(challenge, key.chain, confirm?.chain, device, report) else null
            val proofSignature = evidence?.let { bytes ->
                withContext(Dispatchers.Default) { attester.signer(alias).run { update(bytes); sign() } }
            }
            val token = integrity?.token(evidence?.let(RequestHash::enrollmentEvidence)
                ?: RequestHash.enrollment(challenge.nonce, key.publicKeySpki))
            val result = api.enroll(
                EnrollmentRequest(
                    challengeId = challenge.challengeId,
                    attestationChain = key.chain,
                    playIntegrityToken = token,
                    device = device,
                    confirmKeyChain = confirm?.chain,
                    signals = report,
                    evidenceData = evidence,
                    evidenceSignature = proofSignature,
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

    /**
     * Run 17: ask the server to verify the phone now.
     *
     * Never throws for remote problems and never reports a local result as server-verified:
     * every failure becomes [ServerScan.Unavailable]. Use [ServerScan.label] to present it.
     *
     * @param freshAttestation generate a short-lived attested key for the scan nonce (deleted
     *   afterwards). Without it the server reports freshAttestation NOT_PROVIDED, and the
     *   default server policy rejects the scan.
     */
    suspend fun verifiedScan(freshAttestation: Boolean = true): ServerScan {
        val enrollment = store.load() ?: return ServerScan.Unavailable(UnavailableReason.NOT_ENROLLED)
        val ephemeral = newAlias()
        return try {
            val challenge = api.createDeviceChallenge(enrollment.deviceId, ScanEvidence.PURPOSE_SCAN)
            val fresh = if (freshAttestation) {
                // A device that cannot make one more key still gets a (partial) server verdict.
                withContext(Dispatchers.Default) { runCatching { attester.generate(ephemeral, challenge.nonce) }.getOrNull() }
            } else {
                null
            }
            val report = collectSignals()?.let { JSONObject(it.toString()) }
            val data = ScanEvidence.scan(enrollment.deviceId, challenge, clockMillis(), fresh?.chain, deviceInfo(), report)
            val signature = try {
                withContext(Dispatchers.Default) { attester.signer(enrollment.keyAlias).run { update(data); sign() } }
            } catch (e: NotEnrolledException) {
                // The enrolled key is gone from this keystore (reset, restored backup): enroll again.
                return ServerScan.Unavailable(UnavailableReason.KEY_UNAVAILABLE)
            }
            val token = integrity?.let { source -> playToken(source, RequestHash.scanEvidence(data)) }
            api.verifyScan(ScanRequest(enrollment.deviceId, challenge.challengeId, data, signature, fresh?.chain, token))
                .copy(playRequested = integrity != null)
        } catch (e: CancellationException) {
            throw e
        } catch (e: NotEnrolledException) {
            // 404 from the server: unknown, not owned, pending, revoked or quarantined.
            ServerScan.Unavailable(UnavailableReason.DEVICE_NOT_ACTIVE)
        } catch (e: MalformedResponseException) {
            ServerScan.Unavailable(UnavailableReason.MALFORMED_RESPONSE, e.message)
        } catch (e: HttpStatusException) {
            ServerScan.Unavailable(UnavailableReason.SERVER_ERROR, "HTTP ${e.code}")
        } catch (e: UnsupportedOperationException) {
            ServerScan.Unavailable(UnavailableReason.UNSUPPORTED_TRANSPORT, e.message)
        } catch (e: DeviceTrustException) {
            ServerScan.Unavailable(UnavailableReason.NETWORK, e.message)
        } finally {
            attester.delete(ephemeral)
        }
    }

    private suspend fun playToken(source: IntegrityTokenSource, hash: String): String? = try {
        source.token(hash)
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        null // the server reports Play as NOT_PROVIDED; the label shows the gap
    }

    /**
     * Run 17: replace the enrolled keys with new ones the current device key authorises.
     *
     * Only when the server answers `rotated` does the client switch to the new keys and
     * delete the old ones; any other outcome deletes the new keys and keeps the old ones.
     * If the response is lost after the server rotated, the old key no longer verifies:
     * enroll again. This is not proof that old and new keys share one physical phone.
     *
     * @throws NotEnrolledException if not enrolled or the server does not know the device as active.
     */
    suspend fun rotateKeys(withConfirmKey: Boolean = true): KeyRotationResult {
        val enrollment = store.load() ?: throw NotEnrolledException()
        val challenge = api.createDeviceChallenge(enrollment.deviceId, ScanEvidence.PURPOSE_KEY_ROTATION)
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
            val data = ScanEvidence.keyRotation(enrollment.deviceId, challenge, clockMillis(), key.chain, confirm?.chain, deviceInfo())
            val (oldSignature, newSignature) = withContext(Dispatchers.Default) {
                attester.signer(enrollment.keyAlias).run { update(data); sign() } to
                    attester.signer(alias).run { update(data); sign() }
            }
            // Run 28: the new key meets the same Play requirement as at enrollment.
            val token = integrity?.let { source -> playToken(source, RequestHash.keyRotation(data)) }
            val result = api.rotateKey(
                KeyRotationRequest(enrollment.deviceId, challenge.challengeId, data, oldSignature, newSignature, key.chain,
                    confirm?.chain, token),
            )
            if (result.rotated) {
                store.save(Enrollment(enrollment.deviceId, alias, confirm?.alias))
                keep = true
                attester.delete(enrollment.keyAlias)
                enrollment.confirmKeyAlias?.let { attester.delete(it) }
            }
            return result
        } finally {
            if (!keep) {
                attester.delete(alias)
                attester.delete(confirmAlias)
            }
        }
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
