package com.devicetrust.client

import com.devicetrust.client.signals.AccessibilityServiceRef
import com.devicetrust.client.signals.CheckReason
import com.devicetrust.client.signals.DeviceSignals
import com.devicetrust.client.signals.FakeProbe
import com.devicetrust.client.signals.PathState
import com.devicetrust.client.signals.TextRead
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Integration of Run 14 (typed signal coverage) with Run 20 (signed enrollment
 * transcript): the complete signal report, including UNAVAILABLE states and
 * nulls, is signed as-is and the largest realistic transcript stays inside the
 * server's 32 KiB / depth 32 / 8,192-node bounds. CI re-checks the written
 * fixtures with the Python parser (tools/check_enrollment_fixtures.py).
 */
class EnrollmentCoverageFixtureTest {
    private val maxDevice = DeviceInfo("b".repeat(128), "d".repeat(128), "p".repeat(128), "m".repeat(128), "x".repeat(128))
    private val challenge = Challenge("c".repeat(128), ByteArray(32) { it.toByte() }, 120)
    /** Ten certificates on each chain: the server's maximum chain length. */
    private val chain = List(10) { ByteArray(600) { i -> (i + it).toByte() } }

    private fun detected(): JSONObject = DeviceSignals(FakeProbe().apply {
        files += setOf("/system/xbin/su", "/data/adb/modules", "/dev/qemu_pipe")
        packages += DeviceSignals.ROOT_APPS + DeviceSignals.REMOTE_ACCESS_APPS.values.flatten()
        texts["/proc/self/maps"] = "frida-agent zygisk liblspd"
        texts["/proc/self/status"] = "TracerPid:\t42\n"
        openPorts += DeviceSignals.FRIDA_PORTS
        installer = "com.other.store"
        a11y = DeviceSignals.REMOTE_ACCESS_APPS.values.flatten().map { AccessibilityServiceRef(it, false) }
    }).collect()

    private fun unavailable(): JSONObject = DeviceSignals(object : FakeProbe() {
        override fun readTextResult(path: String) = TextRead.Failed(CheckReason.ACCESS_DENIED)
        override fun pathState(path: String) = PathState.INACCESSIBLE
        override fun installerPackage(): String? = throw IllegalStateException()
        override fun signingCertSha256(): String? = null
        override fun enabledAccessibilityServices(): List<AccessibilityServiceRef> = throw SecurityException()
    }).collect()

    private fun transcript(signals: JSONObject): ByteArray =
        EnrollmentProof.data(challenge, chain, chain, maxDevice, signals)

    @Test
    fun fullCoverageTranscriptsFitTheServerBounds() {
        val out = File("build").apply { mkdirs() }
        for ((name, signals) in listOf("detected" to detected(), "unavailable" to unavailable())) {
            val data = transcript(signals)
            assertTrue("$name transcript is ${data.size} bytes", data.size <= 32 * 1024)
            val doc = JSONObject(data.toString(Charsets.UTF_8))
            assertEquals(1, doc.getJSONObject("signals").getInt("signal_coverage_version"))
            File(out, "enrollment-transcript-$name.json").writeBytes(data)
        }
    }

    @Test
    fun signedSignalsAreExactlyTheCollectedSnapshot() {
        val signals = unavailable()
        val doc = JSONObject(transcript(signals).toString(Charsets.UTF_8)).getJSONObject("signals")
        assertEquals(signals.keySet(), doc.keySet())
        assertEquals("UNAVAILABLE", doc.getString("root_su_status"))
        assertTrue(doc.isNull("app_installer"))
        assertEquals("UNAVAILABLE", doc.getString("app_installer_status"))
        assertTrue(doc.isNull("app_signature_sha256"))
    }
}
