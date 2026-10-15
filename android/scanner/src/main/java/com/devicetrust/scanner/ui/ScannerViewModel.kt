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
import com.devicetrust.client.ServerScan
import com.devicetrust.scanner.scan.ApkDigest
import com.devicetrust.scanner.scan.LabRecord
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
    var cloudProject by mutableStateOf(prefs.getString("cloud_project", "").orEmpty())
        private set
    var serverScan by mutableStateOf<ServerScan?>(null)
        private set
    /** Run 30: the latest server-verified scan with its measured duration, for lab records. */
    private var serverRun: LabRecord.ServerRun? = null

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

    fun updateCloudProject(value: String) {
        cloudProject = value.filter(Char::isDigit)
        prefs.edit().putString("cloud_project", cloudProject).apply()
    }

    private fun serverTest(activity: FragmentActivity) =
        ServerTest(activity, serverUrl, cloudProject.toLongOrNull())

    private fun launchServer(block: suspend () -> Unit) {
        if (serverRunning) return
        serverRunning = true
        serverError = null
        viewModelScope.launch {
            try {
                block()
            } catch (e: Exception) {
                serverError = e.message ?: e.javaClass.simpleName
            } finally {
                serverRunning = false
            }
        }
    }

    /** Run 17: a server verdict on this phone now; every failure is shown as "not server-verified". */
    fun runVerifiedScan(activity: FragmentActivity) = launchServer {
        serverScan = null
        val started = System.currentTimeMillis()
        val result = serverTest(activity).verifiedScan()
        val finished = System.currentTimeMillis()
        serverRun = LabRecord.ServerRun(result, finished - started, finished)
        serverScan = result
    }

    /** Run 30: builds the lab record off the main thread and hands it to [onReady] on the main thread. */
    fun withLabRecord(onReady: (String) -> Unit) {
        viewModelScope.launch { onReady(labRecord()) }
    }

    /** Run 30: the lab record for the latest local and server-verified scans (hashes the APK off the main thread). */
    suspend fun labRecord(): String = withContext(Dispatchers.IO) {
        val app: Application = getApplication()
        val version = runCatching { app.packageManager.getPackageInfo(app.packageName, 0).versionName }.getOrNull()
        LabRecord.build(
            apkSha256 = ApkDigest.of(app),
            scannerVersion = version ?: "unknown",
            os = "Android ${android.os.Build.VERSION.RELEASE} (API ${android.os.Build.VERSION.SDK_INT})",
            local = (scan as? ScanState.Done)?.result,
            server = serverRun,
            nowMillis = System.currentTimeMillis(),
        ).toString(2)
    }

    fun runKeyRotation(activity: FragmentActivity) = launchServer {
        serverSteps.add(serverTest(activity).rotateKeys())
    }

    fun runServer(activity: FragmentActivity) {
        if (serverRunning) return
        serverRunning = true
        serverSteps.clear()
        serverScan = null
        serverError = null
        viewModelScope.launch {
            try {
                serverTest(activity).run { serverSteps.add(it) }
            } catch (e: Exception) {
                serverError = e.message ?: e.javaClass.simpleName
            } finally {
                serverRunning = false
            }
        }
    }
}
