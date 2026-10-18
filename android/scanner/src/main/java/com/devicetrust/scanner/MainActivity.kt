package com.devicetrust.scanner

import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.devicetrust.scanner.ui.BiometricScreen
import com.devicetrust.scanner.ui.ScanScreen
import com.devicetrust.scanner.ui.ScannerViewModel
import com.devicetrust.scanner.ui.ServerScreen

/** FragmentActivity (not plain ComponentActivity) because BiometricPrompt needs one. */
class MainActivity : FragmentActivity() {
    private val vm: ScannerViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent { ScannerTheme { App() } }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun App() {
        var tab by rememberSaveable { mutableIntStateOf(0) }
        Scaffold(
            topBar = { TopAppBar(title = { Text("Device Trust Scanner") }) },
            bottomBar = {
                NavigationBar {
                    NavigationBarItem(tab == 0, { tab = 0 }, { Icon(Icons.Filled.Shield, null) }, label = { Text("Scan") })
                    NavigationBarItem(tab == 1, { tab = 1 }, { Icon(Icons.Filled.Fingerprint, null) }, label = { Text("Biometric") })
                    NavigationBarItem(tab == 2, { tab = 2 }, { Icon(Icons.Filled.Cloud, null) }, label = { Text("Server") })
                }
            },
        ) { padding ->
            Column(
                Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(16.dp),
            ) {
                when (tab) {
                    0 -> ScanScreen(vm.scan, vm::runScan, vm::debugReport)
                    1 -> BiometricScreen(vm.biometricRunning, vm.biometricChecks) { vm.runBiometric(this@MainActivity) }
                    else -> ServerScreen(
                        vm.serverUrl, vm::updateServerUrl, vm.serverRunning, vm.serverSteps, vm.serverError,
                        onRun = { vm.runServer(this@MainActivity) },
                        cloudProject = vm.cloudProject,
                        onCloudProject = vm::updateCloudProject,
                        serverScan = vm.serverScan,
                        onVerifiedScan = { vm.runVerifiedScan(this@MainActivity) },
                        onRotateKeys = { vm.runKeyRotation(this@MainActivity) },
                        onShareLabRecord = { shareLabRecord(vm) },
                        buildReport = vm::debugReport,
                    )
                }
            }
        }
    }
}

/** Run 30: share the measured lab record; the operator adds case, alias and outcome on a computer. */
private fun FragmentActivity.shareLabRecord(vm: ScannerViewModel) {
    vm.withLabRecord { record ->
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/json"
            putExtra(Intent.EXTRA_SUBJECT, "Cyclone Scan lab record")
            putExtra(Intent.EXTRA_TEXT, record)
        }
        startActivity(Intent.createChooser(send, "Share lab record"))
    }
}

@Composable
private fun ScannerTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = colors, content = content)
}
