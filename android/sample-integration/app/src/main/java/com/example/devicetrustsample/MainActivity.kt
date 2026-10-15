package com.example.devicetrustsample

import android.os.Bundle
import android.widget.TextView
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.devicetrust.client.Decision
import com.devicetrust.client.DeviceTrustClient
import com.devicetrust.client.HttpTrustApi
import com.devicetrust.client.ScanLabel
import com.devicetrust.client.ServerScan
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Minimal integration of the Device Trust SDK, consumed as a Maven artifact:
 * enroll, run a server-verified scan, sign one action for the backend to verify.
 *
 * The SDK only collects evidence. Your backend authenticates the user, forwards
 * requests to the verification service (with the gateway principal), and executes
 * only the action the service returns.
 */
class MainActivity : FragmentActivity() {
    private lateinit var log: TextView

    private val trust by lazy {
        val api = HttpTrustApi(
            baseUrl = BuildConfig.TRUST_API,
            // Your app session credential, checked by your backend (never a service secret).
            headers = { mapOf("Authorization" to "Bearer ${sessionToken()}") },
        )
        DeviceTrustClient(this, api, cloudProjectNumber = null) // set your Cloud project to request Play Integrity
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        log = TextView(this).apply { setPadding(32, 32, 32, 32) }
        setContentView(log)
        lifecycleScope.launch { runFlow() }
    }

    private suspend fun runFlow() {
        try {
            // Enroll once; later launches reuse the stored enrollment.
            val enrollment = if (trust.currentEnrollment() == null) trust.enroll() else null
            enrollment?.let { show("Enrollment: ${it.decision} (${it.deviceStatus ?: "status not reported"})") }
            if (enrollment?.decision == Decision.BLOCK) return

            when (val scan = trust.verifiedScan()) {
                is ServerScan.Verified -> show(
                    when (scan.label(System.currentTimeMillis())) {
                        ScanLabel.VERIFIED_FRESH -> "Server-verified: ${scan.decision}"
                        ScanLabel.VERIFIED_PARTIAL -> "Server-verified (partial: ${scan.partialBecause().joinToString()})"
                        ScanLabel.VERIFIED_EXPIRED -> "Server verdict expired; scan again"
                        ScanLabel.REJECTED -> "Server rejected the scan (${scan.decisionId})"
                        ScanLabel.UNAVAILABLE -> "Not server-verified"
                    },
                )
                is ServerScan.Unavailable -> show("Not server-verified: ${scan.reason}")
            }

            val signed = trust.signAction("login", JSONObject())
            show("Signed action ${signed.challengeId}: send it to your backend for verification")
        } catch (e: Exception) {
            show("Error: ${e.message}")
        }
    }

    private fun show(line: String) {
        log.append(line + "\n")
    }

    private fun sessionToken(): String = "replace-with-your-app-session"
}
