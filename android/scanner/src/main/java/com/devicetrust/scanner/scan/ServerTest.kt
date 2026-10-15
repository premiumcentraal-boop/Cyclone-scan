package com.devicetrust.scanner.scan

import androidx.fragment.app.FragmentActivity
import com.devicetrust.client.AndroidKeyAttester
import com.devicetrust.client.BiometricPromptAuthenticator
import com.devicetrust.client.DeviceTrustClient
import com.devicetrust.client.EnrollmentStore
import com.devicetrust.client.HttpTrustApi
import com.devicetrust.client.PlayIntegrityTokenSource
import com.devicetrust.client.ServerDiagnostics
import com.devicetrust.client.ServerScan
import com.devicetrust.client.SharedPreferencesEnrollmentStore
import com.devicetrust.client.signals.AndroidSignalProbe
import com.devicetrust.client.signals.DeviceSignals
import org.json.JSONObject

/** One step of the end-to-end test against a real Device Trust Service. */
data class ServerStep(val title: String, val decision: String, val detail: String, val diagnostics: ServerDiagnostics?)

/**
 * Full product flow against a running server: enroll (attestation + signals,
 * plus the confirm key when available), sign a low-risk login, and sign a
 * biometric-confirmed payment. Run the server with --expose-reasons to see
 * reason codes and risk factors.
 */
class ServerTest(private val activity: FragmentActivity, baseUrl: String, cloudProjectNumber: Long? = null) {
    private val store: EnrollmentStore = SharedPreferencesEnrollmentStore(activity)
    // Cleartext only for LAN testing against a laptop; production must be HTTPS.
    private val api = HttpTrustApi(baseUrl.trim(), allowCleartextForTesting = baseUrl.trim().startsWith("http://"))
    private val client = DeviceTrustClient(
        api = api,
        attester = AndroidKeyAttester(activity),
        // Without a Cloud project the scan result says Play Integrity was not requested.
        integrity = cloudProjectNumber?.let { PlayIntegrityTokenSource(activity, it) },
        store = store,
        signals = DeviceSignals(AndroidSignalProbe(activity)),
    )

    /** Run 17: server-verified scan of the current enrollment (repeat it to build history). */
    suspend fun verifiedScan(): ServerScan = client.verifiedScan()

    /** Run 17: replace the enrolled keys with new ones the current key authorises. */
    suspend fun rotateKeys(): ServerStep {
        val result = client.rotateKeys(withConfirmKey = true)
        return ServerStep("Key rotation", result.decision.name,
            if (result.rotated) "new keys in use" + if (result.hasConfirmKey == true) " · new biometric key" else ""
            else "not rotated: the old keys stay in use", result.diagnostics)
    }

    suspend fun run(onStep: (ServerStep) -> Unit) {
        client.reset()
        val enrolled = client.enroll(withConfirmKey = true)
        onStep(ServerStep("Enrollment", enrolled.decision.name,
            enrolled.deviceId?.let { "device $it" + if (client.hasConfirmKey()) " · biometric key enrolled" else "" }
                ?: "not enrolled", enrolled.diagnostics))
        if (enrolled.deviceId == null) return
        if (enrolled.deviceStatus == "pending") {
            // Run 16: pending devices cannot sign actions until the app's backend verifies the account owner.
            onStep(ServerStep("Device status", "PENDING",
                "enrolled, awaiting account step-up by the app's backend; protected actions are refused until then",
                null))
            return
        }

        val login = client.signAction("login")
        val loginResult = api.verifyAction(login)
        onStep(ServerStep("Signed login", loginResult.decision.name, "signed by device key", loginResult.diagnostics))

        val params = JSONObject().put("payee", "NL91TEST0000000000").put("amountCents", 100).put("currency", "EUR")
        val payment = if (client.hasConfirmKey()) {
            client.signAction("payment", params,
                BiometricPromptAuthenticator(activity, "Confirm payment", "€1.00 to NL91 TEST 0000 0000 00"))
        } else {
            client.signAction("payment", params)
        }
        val paymentResult = api.verifyAction(payment)
        onStep(ServerStep(
            "Biometric payment",
            paymentResult.decision.name,
            (if (payment.key.wire == "confirm") "signed by biometric key" else "no biometric key: device key") +
                (paymentResult.paramsJson?.let { " · server returned $it" } ?: ""),
            paymentResult.diagnostics,
        ))
    }
}
