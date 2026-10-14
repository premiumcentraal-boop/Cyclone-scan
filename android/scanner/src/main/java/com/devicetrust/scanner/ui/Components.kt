package com.devicetrust.scanner.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.QuestionMark
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.devicetrust.scanner.attest.Check

val Green = Color(0xFF1E8E3E)
val Amber = Color(0xFFE37400)
val Red = Color(0xFFD93025)
val Blue = Color(0xFF1A73E8)
val Grey = Color(0xFF5F6368)

fun statusColor(status: Check.Status) = when (status) {
    Check.Status.PASS -> Green
    Check.Status.WARN -> Amber
    Check.Status.FAIL -> Red
    Check.Status.INFO -> Blue
    Check.Status.UNVERIFIED -> Grey
}

@Composable
fun StatusIcon(status: Check.Status) {
    val icon = when (status) {
        Check.Status.PASS -> Icons.Filled.CheckCircle
        Check.Status.WARN -> Icons.Filled.Warning
        Check.Status.FAIL -> Icons.Filled.Error
        Check.Status.INFO -> Icons.Filled.Info
        Check.Status.UNVERIFIED -> Icons.Filled.QuestionMark
    }
    Icon(icon, contentDescription = if (status == Check.Status.UNVERIFIED) "could not verify" else status.name, tint = statusColor(status), modifier = Modifier.size(20.dp))
}

@Composable
fun CheckRow(label: String, status: Check.Status, detail: String = "") {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.Top,
    ) {
        StatusIcon(status)
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            if (detail.isNotBlank()) {
                Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
fun SectionCard(title: String, subtitle: String? = null, content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Spacer(Modifier.padding(top = 4.dp))
            content()
        }
    }
}
