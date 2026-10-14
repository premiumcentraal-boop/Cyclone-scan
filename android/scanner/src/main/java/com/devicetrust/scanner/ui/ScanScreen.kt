package com.devicetrust.scanner.ui

import android.content.Intent
import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.risk.LocalRisk
import com.devicetrust.scanner.scan.LayerState
import com.devicetrust.scanner.scan.ScanResult
import com.devicetrust.scanner.scan.Verdict

@Composable
fun ScanScreen(state: ScanState, onScan: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        SectionCard(
            title = "${Build.MANUFACTURER} ${Build.MODEL}",
            subtitle = "Android ${Build.VERSION.RELEASE} · API ${Build.VERSION.SDK_INT}",
        ) {
            Text(
                "Local diagnostic: creates a hardware-backed key, verifies its attestation against Google's roots and " +
                    "revocation list, checks for root, hooking, emulators, tampering and scam signals, " +
                    "then scores the phone with the same weights the server uses. Play Integrity and server checks " +
                    "do not run in this mode.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))
            Button(onClick = onScan, enabled = state != ScanState.Running, modifier = Modifier.fillMaxWidth()) {
                if (state == ScanState.Running) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    Spacer(Modifier.width(8.dp))
                    Text("Scanning…")
                } else {
                    Text(if (state is ScanState.Done) "Scan again" else "Scan this phone")
                }
            }
        }
        when (state) {
            is ScanState.Done -> ScanResultView(state.result)
            is ScanState.Failed -> SectionCard("Scan failed") { Text(state.message, color = Red) }
            else -> Unit
        }
    }
}

@Composable
private fun ScanResultView(result: ScanResult) {
    val context = LocalContext.current
    val layers = result.layers
    VerdictCard(result)

    SectionCard("Verification coverage", "Local mode · what ran on this phone and what did not") {
        layers.forEach { layer ->
            CheckRow(layer.label, layerStatus(layer.state), layerText(layer.state) + " · " + layer.detail)
        }
    }

    if (result.hardFailures.isNotEmpty()) {
        SectionCard("Blocking findings", "Hard gates: any one of these blocks the device regardless of score") {
            result.hardFailures.forEach { CheckRow(it.label, it.status, it.detail) }
        }
    }

    if (result.factors.any { it.second > 0 }) {
        SectionCard("Why this score", "Each finding adds risk points (same weights as the server)") {
            result.factors.filter { it.second > 0 }.forEach { (factor, points) ->
                Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(LocalRisk.DESCRIPTIONS[factor] ?: factor, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    Text("+$points", fontWeight = FontWeight.SemiBold, color = if (points >= 40) Red else Amber)
                }
            }
        }
    }

    SectionCard(
        "Hardware attestation",
        "Proof from the phone's secure hardware, signed up to Google's root" +
            (result.attestation.rootSubject?.let { " ($it)" } ?: ""),
    ) {
        result.attestation.checks.forEach { CheckRow(it.label, it.status, it.detail) }
    }

    signalGroups(result.signals, result.factors, result.evidence, result.attestedSignerAvailable).forEach { group ->
        SectionCard(group.title) { group.rows.forEach { CheckRow(it.label, it.status, it.detail) } }
    }

    SectionCard("About this result", "Scan took ${result.durationMs} ms") {
        Text(
            "Local mode: the phone judged itself, so a fully compromised phone could lie here. In production the " +
                "evidence goes to the server, which makes the decision. This scan does not evaluate Play Integrity, " +
                "fleet history or an independently trusted scanner signing certificate. Missing checks are not proof of safety.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = {
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = "application/json"
                    putExtra(Intent.EXTRA_SUBJECT, "Device scan: ${result.device.manufacturer} ${result.device.model}")
                    putExtra(Intent.EXTRA_TEXT, result.toJson().toString(2))
                }
                context.startActivity(Intent.createChooser(send, "Share scan report"))
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Filled.Share, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Share diagnostic report (JSON)")
        }
    }
}

@Composable
private fun VerdictCard(result: ScanResult) {
    val (color, icon, title, line) = when (result.verdict) {
        Verdict.ALLOW -> Quad(Green, Icons.Filled.GppGood, "No blocking local findings", "Diagnostic only · server verification required")
        Verdict.STEP_UP -> Quad(Amber, Icons.Filled.GppMaybe, "Local risk indicators", "Review findings with server verification")
        Verdict.BLOCK -> Quad(Red, Icons.Filled.GppBad, "Blocking local findings", "Inspect failed or unavailable checks")
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.12f)),
    ) {
        Column(Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(48.dp))
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, color = color)
                    Text(line, style = MaterialTheme.typography.bodyMedium)
                }
            }
            Spacer(Modifier.height(16.dp))
            Row(verticalAlignment = Alignment.Bottom) {
                Text("${result.score}", style = MaterialTheme.typography.displaySmall, fontWeight = FontWeight.Bold, color = color)
                Text(" / 100 risk", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(bottom = 6.dp))
            }
            Spacer(Modifier.height(6.dp))
            LinearProgressIndicator(
                progress = { result.score / 100f },
                modifier = Modifier.fillMaxWidth().height(8.dp),
                color = color,
                trackColor = Color.Gray.copy(alpha = 0.2f),
            )
            val incomplete = result.findings.count { !it.state.completed }
            if (incomplete > 0) {
                Spacer(Modifier.height(6.dp))
                Text(
                    "$incomplete on-phone check(s) could not be verified. A low score is not evidence that they are clean.",
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                "Risk points, not a probability · allow below ${LocalRisk.ALLOW_BELOW} · step-up below ${LocalRisk.BLOCK_AT} · block at ${LocalRisk.BLOCK_AT}+",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private data class Quad(
    val color: Color,
    val icon: androidx.compose.ui.graphics.vector.ImageVector,
    val title: String,
    val line: String,
)

private fun layerStatus(state: LayerState): Check.Status = when (state) {
    LayerState.VERIFIED, LayerState.COMPLETE -> Check.Status.PASS
    LayerState.FAILED -> Check.Status.FAIL
    LayerState.PARTIAL, LayerState.UNAVAILABLE, LayerState.NOT_EVALUATED -> Check.Status.UNVERIFIED
}

private fun layerText(state: LayerState): String = when (state) {
    LayerState.VERIFIED -> "verified"
    LayerState.FAILED -> "failed"
    LayerState.COMPLETE -> "all checks completed"
    LayerState.PARTIAL -> "partially completed"
    LayerState.UNAVAILABLE -> "unavailable"
    LayerState.NOT_EVALUATED -> "not evaluated"
}

@Suppress("unused")
private fun Check.Status.isBad() = this == Check.Status.FAIL
