package com.devicetrust.client

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class EnrollmentProofTest {
    @Test fun hashMatchesIndependentServerVector() {
        assertEquals("2ReoUCmfQoCmaFDJhLAbN6NQFmVm5f66IznA6C-LWL8",
            RequestHash.enrollmentEvidence("{\"v\":1}".toByteArray()))
    }
    @Test fun completeTranscriptAndTransportPreserveExactBytes() {
        val device = DeviceInfo("", "", "", "", "test")
        val challenge = Challenge("challenge", byteArrayOf(1, 2), 120)
        val signals = JSONObject().put("v", 1).put("root_su", false)
        val data = EnrollmentProof.data(challenge, listOf(byteArrayOf(3)), null, device, signals)
        val doc = JSONObject(data.toString(Charsets.UTF_8))
        assertEquals("enrollment", doc.getString("purpose"))
        assertEquals("AQI", doc.getString("nonce"))
        assertEquals(setOf("model"), doc.getJSONObject("device").keySet())
        assertTrue(doc.isNull("confirmChainSha256"))
        assertFalse(doc.getJSONObject("signals").getBoolean("root_su"))
        val wire = JSONObject(TrustJson.encodeEnrollment(EnrollmentRequest(
            "challenge", listOf(byteArrayOf(3)), null, device, signals = signals,
            evidenceData = data, evidenceSignature = byteArrayOf(4))))
        assertArrayEquals(data, Base64.getDecoder().decode(wire.getString("evidenceData")))
        assertEquals("BA==", wire.getString("evidenceSignature"))
    }
}
