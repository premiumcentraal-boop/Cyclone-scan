package com.devicetrust.scanner.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.devicetrust.client.signals.AndroidSignalProbe
import com.devicetrust.scanner.risk.LocalRisk
import com.devicetrust.scanner.scan.ServerStep
import org.json.JSONArray
import org.json.JSONObject

@Composable
fun ServerScreen(
    url: String,
    onUrl: (String) -> Unit,
    running: Boolean,
    steps: List<ServerStep>,
    error: String?,
    onRun: () -> Unit,
) {
    val context = LocalContext.current
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionCard("Server mode", "The production flow: the server makes every decision") {
            Text(
                "1. On a computer on the same Wi-Fi:  device-trust serve --policy policy.json --host 0.0.0.0 --expose-reasons\n" +
                    "2. Put this app's identity in policy.json (copy button below).\n" +
                    "3. Enter http://<computer-ip>:8080 and run the test: enrollment, a signed login and a " +
                    "biometric-confirmed payment.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = url,
                onValueChange = onUrl,
                label = { Text("Server URL") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = { copyPolicy(context) }, modifier = Modifier.fillMaxWidth()) {
                Text("Copy policy.json for this app")
            }
            Button(onClick = onRun, enabled = !running && url.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                Text(if (running) "Running…" else "Run server test")
            }
        }
        if (error != null) {
            SectionCard("Error") {
                Text(error, color = Red)
                Text("Check the URL, that the server listens on 0.0.0.0 and that both devices share a network.",
                    style = MaterialTheme.typography.bodySmall)
            }
        }
        steps.forEach { StepCard(it) }
    }
}

@Composable
private fun StepCard(step: ServerStep) {
    val color = when (step.decision) {
        "ALLOW" -> Green
        "STEP_UP" -> Amber
        else -> Red
    }
    SectionCard(step.title, step.detail) {
        Text(step.decision, color = color, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleLarge)
        step.diagnostics?.let { d ->
            d.riskScore?.let { Text("Risk $it / 100", style = MaterialTheme.typography.bodyMedium) }
            d.riskFactors.filter { it.second > 0 }.forEach { (f, p) ->
                Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                    Text(LocalRisk.DESCRIPTIONS[f] ?: f, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                    Text("+$p", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                }
            }
            if (d.reasons.isNotEmpty()) {
                Text("Reasons: ${d.reasons.joinToString()}", style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace)
            }
        } ?: Text("Start the server with --expose-reasons to see why.", style = MaterialTheme.typography.bodySmall)
    }
}

private fun copyPolicy(context: Context) {
    val digest = runCatching { AndroidSignalProbe(context).signingCertSha256() }.getOrNull().orEmpty()
    val policy = JSONObject()
        .put("package_name", context.packageName)
        .put("signing_cert_sha256", JSONArray(listOf(digest)))
        .put("allowed_action_types", JSONArray(listOf("login", "payment")))
        .put("confirm_key_required_actions", JSONArray(listOf("payment")))
        .put("risk", JSONObject().put("trusted_installers", JSONArray(listOf("com.android.vending", "com.google.android.packageinstaller"))))
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    clipboard.setPrimaryClip(ClipData.newPlainText("policy.json", policy.toString(2)))
    Toast.makeText(context, "policy.json copied", Toast.LENGTH_SHORT).show()
}
