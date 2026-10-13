package com.devicetrust.scanner.ui

import android.app.Application
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.scan.BiometricTest
import com.devicetrust.scanner.scan.ScanResult
import com.devicetrust.scanner.scan.Scanner
import com.devicetrust.scanner.scan.ServerStep
import com.devicetrust.scanner.scan.ServerTest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface ScanState {
    data object Idle : ScanState
    data object Running : ScanState
    data class Done(val result: ScanResult) : ScanState
    data class Failed(val message: String) : ScanState
}

class ScannerViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("scanner", Context.MODE_PRIVATE)

    var scan by mutableStateOf<ScanState>(ScanState.Idle)
        private set
    var biometricRunning by mutableStateOf(false)
        private set
    val biometricChecks = mutableStateListOf<Check>()
    var serverUrl by mutableStateOf(prefs.getString("server_url", "http://192.168.1.10:8080").orEmpty())
        private set
    var serverRunning by mutableStateOf(false)
        private set
    val serverSteps = mutableStateListOf<ServerStep>()
    var serverError by mutableStateOf<String?>(null)
        private set

    fun runScan() {
        if (scan == ScanState.Running) return
        scan = ScanState.Running
        viewModelScope.launch {
            scan = try {
                ScanState.Done(withContext(Dispatchers.IO) { Scanner(getApplication()).scan() })
            } catch (e: Exception) {
                ScanState.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    fun runBiometric(activity: FragmentActivity) {
        if (biometricRunning) return
        biometricRunning = true
        biometricChecks.clear()
        viewModelScope.launch {
            try {
                biometricChecks.addAll(BiometricTest(activity).run())
            } finally {
                biometricRunning = false
            }
        }
    }

    fun updateServerUrl(url: String) {
        serverUrl = url
        prefs.edit().putString("server_url", url).apply()
    }

    fun runServer(activity: FragmentActivity) {
        if (serverRunning) return
        serverRunning = true
        serverSteps.clear()
        serverError = null
        viewModelScope.launch {
            try {
                ServerTest(activity, serverUrl).run { serverSteps.add(it) }
            } catch (e: Exception) {
                serverError = e.message ?: e.javaClass.simpleName
            } finally {
                serverRunning = false
            }
        }
    }
}
