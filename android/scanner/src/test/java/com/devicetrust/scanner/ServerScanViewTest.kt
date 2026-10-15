package com.devicetrust.scanner

import com.devicetrust.client.Decision
import com.devicetrust.client.EvidenceStatus
import com.devicetrust.client.HistoryChange
import com.devicetrust.client.ScanEvidenceStatus
import com.devicetrust.client.ScanPolicy
import com.devicetrust.client.ServerScan
import com.devicetrust.client.UnavailableReason
import com.devicetrust.scanner.attest.Check
import com.devicetrust.scanner.scan.ServerScanView
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Run 17: only a server verdict is called server-verified; gaps, expiry and history are stated honestly. */
class ServerScanViewTest {
    private val complete = ScanEvidenceStatus(EvidenceStatus.VERIFIED, EvidenceStatus.VERIFIED, EvidenceStatus.VERIFIED,
        EvidenceStatus.SIGNED)
    private val scan = ServerScan.Verified(Decision.ALLOW, "dec_1", 1_000, 301_000, ScanPolicy("beta", "abcd", "r"),
        complete, null, null, playRequested = true)

    @Test
    fun completeFreshAllowIsServerVerified() {
        val h = ServerScanView.headline(scan, 2_000)
        assertEquals("Server-verified · trusted", h.title)
        assertEquals(ServerScanView.Tone.GOOD, h.tone)
    }

    @Test
    fun partialExpiredRejectedAndUnavailableSayWhatTheyAre() {
        val partial = ServerScanView.headline(scan.copy(evidence = complete.copy(freshAttestation = EvidenceStatus.NOT_PROVIDED)), 2_000)
        assertTrue(partial.title.startsWith("Server-verified (partial)"))
        assertTrue(partial.detail.contains("fresh attestation not provided"))
        assertEquals("Server verdict expired", ServerScanView.headline(scan, 400_000).title)
        assertEquals("Server rejected this scan", ServerScanView.headline(scan.copy(decision = Decision.BLOCK), 2_000).title)
        for (reason in UnavailableReason.values()) {
            val h = ServerScanView.headline(ServerScan.Unavailable(reason), 2_000)
            assertEquals("Not server-verified", h.title)
            assertFalse(h.detail.isBlank())
        }
    }

    @Test
    fun stepUpIsNotShownAsTrusted() {
        val h = ServerScanView.headline(scan.copy(decision = Decision.STEP_UP), 2_000)
        assertEquals("Server-verified · needs extra verification", h.title)
        assertEquals(ServerScanView.Tone.CAUTION, h.tone)
    }

    @Test
    fun missingPlayWithoutCloudProjectIsExplained() {
        val noPlay = scan.copy(playRequested = false, evidence = complete.copy(playIntegrity = EvidenceStatus.NOT_PROVIDED))
        assertTrue(ServerScanView.headline(noPlay, 2_000).detail.contains("no Cloud project configured"))
        val row = ServerScanView.evidenceRows(noPlay).first { it.label == "Play Integrity" }
        assertEquals(Check.Status.UNVERIFIED, row.status)
        assertTrue(row.detail.contains("Cloud project number"))
    }

    @Test
    fun evidenceStatusesNeverLookLikeAPassUnlessVerified() {
        for (s in EvidenceStatus.values()) {
            assertEquals(s == EvidenceStatus.VERIFIED, ServerScanView.status(s) == Check.Status.PASS)
        }
    }

    @Test
    fun historyFindingsAreExplainedWithoutClaimingTheSamePhone() {
        val fresh = ServerScanView.explain(HistoryChange("FRESH_KEY_AUTHORIZED", "INFO", "leaf_spki_sha256"))
        assertTrue(fresh.contains("does not prove it is the same physical phone"))
        assertTrue(ServerScanView.explain(HistoryChange("BOOT_IMAGE_CHANGED", "INFO", "verified_boot_hash"))
            .contains("expected after a system update"))
        assertEquals(Check.Status.WARN, ServerScanView.level(HistoryChange("PATCH_REGRESSION", "REVIEW", "os_patch_level")))
        assertEquals(Check.Status.INFO, ServerScanView.level(HistoryChange("BOOT_IMAGE_CHANGED", "INFO", "x")))
        assertEquals("NEW_CODE (f)", ServerScanView.explain(HistoryChange("NEW_CODE", "INFO", "f")))
    }
}
