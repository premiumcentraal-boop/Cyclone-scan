package com.devicetrust.scanner.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.devicetrust.scanner.attest.Check

@Composable
fun BiometricScreen(running: Boolean, checks: List<Check>, onRun: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionCard(
            "Biometric-confirmed payments",
            "The secure hardware proves a key can only sign after your fingerprint or face",
        ) {
            Text(
                "Creates a confirm key, checks the hardware's attestation of its rules (strong biometric only, " +
                    "fresh authentication for every signature), then asks you to approve a €1.00 test payment " +
                    "and verifies the resulting signature. Nothing is sent anywhere.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))
            Button(onClick = onRun, enabled = !running, modifier = Modifier.fillMaxWidth()) {
                Text(if (running) "Waiting for authentication…" else "Run biometric test")
            }
        }
        if (checks.isNotEmpty()) {
            SectionCard("Result") { checks.forEach { CheckRow(it.label, it.status, it.detail) } }
        }
    }
}
