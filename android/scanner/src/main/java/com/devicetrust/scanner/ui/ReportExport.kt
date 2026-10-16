package com.devicetrust.scanner.ui

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.devicetrust.scanner.scan.DebugReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Run 31: "Save report file" (Android's file picker, e.g. Downloads) and "Share report
 * file" (a real .json attachment for mail, chat or Drive). Both export the same
 * [DebugReport]: results, everything that could not be scanned and why, errors and context.
 */
@Composable
fun ReportExportButtons(buildReport: suspend () -> DebugReport.Export, enabled: Boolean = true) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pending by remember { mutableStateOf<DebugReport.Export?>(null) }
    var busy by remember { mutableStateOf(false) }
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val report = pending
        pending = null
        if (uri == null || report == null) return@rememberLauncherForActivityResult
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(report.json.toByteArray()) }
                        ?: error("no output stream")
                }.isSuccess
            }
            Toast.makeText(context, if (ok) "Report saved" else "Could not save the report", Toast.LENGTH_SHORT).show()
        }
    }

    fun withReport(action: (DebugReport.Export) -> Unit) {
        if (busy) return
        busy = true
        scope.launch {
            try {
                action(buildReport())
            } catch (e: Exception) {
                Toast.makeText(context, "Could not build the report: ${e.javaClass.simpleName}", Toast.LENGTH_LONG).show()
            } finally {
                busy = false
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Button(
            onClick = { withReport { report -> pending = report; save.launch(report.fileName) } },
            enabled = enabled && !busy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Filled.Download, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Save report file")
        }
        OutlinedButton(
            onClick = { withReport { report -> scope.launch { shareReport(context, report) } } },
            enabled = enabled && !busy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Filled.Share, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Share report file")
        }
    }
}

private suspend fun shareReport(context: Context, report: DebugReport.Export) {
    val file = withContext(Dispatchers.IO) {
        val dir = File(context.cacheDir, "reports").apply { mkdirs() }
        // Keep only the report being shared; older exports are not left behind in the cache.
        dir.listFiles()?.forEach { it.delete() }
        File(dir, report.fileName).apply { writeText(report.json) }
    }
    val uri = FileProvider.getUriForFile(context, context.packageName + ".reports", file)
    val send = Intent(Intent.ACTION_SEND).apply {
        type = "application/json"
        putExtra(Intent.EXTRA_STREAM, uri)
        putExtra(Intent.EXTRA_SUBJECT, report.fileName)
        clipData = ClipData.newRawUri(report.fileName, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(send, "Share scan report"))
}
