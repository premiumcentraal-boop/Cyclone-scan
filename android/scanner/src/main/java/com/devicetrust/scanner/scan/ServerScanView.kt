package com.devicetrust.scanner.scan

import com.devicetrust.client.Decision
import com.devicetrust.client.EvidenceStatus
import com.devicetrust.client.HistoryChange
import com.devicetrust.client.ScanLabel
import com.devicetrust.client.ServerScan
import com.devicetrust.client.UnavailableReason
import com.devicetrust.scanner.attest.Check
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Run 17: what the scanner shows for a server-verified scan. Pure, so the wording rules
 * are unit-tested: only a server verdict can be called "server-verified", a partial or
 * expired verdict says so, and history findings are explained as observations about
 * attested evidence, not as proof of compromise or of "the same phone".
 */
object ServerScanView {
    enum class Tone { GOOD, CAUTION, BAD, NEUTRAL }

    data class Headline(val title: String, val detail: String, val tone: Tone)

    data class Row(val label: String, val status: Check.Status, val detail: String)

    fun headline(scan: ServerScan, nowMillis: Long): Headline = when (scan) {
        is ServerScan.Unavailable -> Headline("Not server-verified", unavailableText(scan.reason), Tone.NEUTRAL)
        is ServerScan.Verified -> when (scan.label(nowMillis)) {
            ScanLabel.REJECTED -> Headline("Server rejected this scan",
                "Decision ${scan.decision.name} · look up ${scan.decisionId} in the server's decision log", Tone.BAD)
            ScanLabel.VERIFIED_EXPIRED -> Headline("Server verdict expired",
                "Verified ${time(scan.verifiedAtMillis)}; valid for display until ${time(scan.freshUntilMillis)}. Scan again.",
                Tone.NEUTRAL)
            ScanLabel.VERIFIED_PARTIAL -> Headline("Server-verified (partial) · ${decisionText(scan.decision)}",
                "Missing: " + scan.partialBecause().joinToString("; "),
                if (scan.decision == Decision.ALLOW) Tone.CAUTION else Tone.BAD)
            ScanLabel.VERIFIED_FRESH -> Headline("Server-verified · ${decisionText(scan.decision)}",
                "Signature, fresh hardware attestation and Play Integrity verified by the server",
                if (scan.decision == Decision.ALLOW) Tone.GOOD else Tone.CAUTION)
            ScanLabel.UNAVAILABLE -> Headline("Not server-verified", "No server verdict", Tone.NEUTRAL)
        }
    }

    fun decisionText(decision: Decision) = when (decision) {
        Decision.ALLOW -> "trusted"
        Decision.STEP_UP -> "needs extra verification"
        Decision.BLOCK -> "not trusted"
    }

    fun unavailableText(reason: UnavailableReason) = when (reason) {
        UnavailableReason.NOT_ENROLLED -> "This phone is not enrolled. Run the server test first."
        UnavailableReason.DEVICE_NOT_ACTIVE ->
            "The server does not accept scans for this enrollment (unknown, pending step-up, revoked or needs re-enrollment)."
        UnavailableReason.KEY_UNAVAILABLE -> "The enrolled key is no longer on this phone. Enroll again."
        UnavailableReason.NETWORK -> "The server could not be reached."
        UnavailableReason.SERVER_ERROR -> "The server returned an error."
        UnavailableReason.MALFORMED_RESPONSE -> "The server's answer was not in the expected format; it was not trusted."
        UnavailableReason.UNSUPPORTED_TRANSPORT -> "This build's server connection does not support verified scans."
    }

    fun evidenceRows(scan: ServerScan.Verified): List<Row> = listOf(
        Row("Signed by the enrolled key", status(scan.evidence.deviceKeySignature),
            "Proves the request came from the holder of the enrolled hardware key"),
        Row("Fresh hardware attestation", status(scan.evidence.freshAttestation),
            "A new key attested for this scan's one-time challenge: current boot, lock and patch state"),
        Row("Play Integrity", status(scan.evidence.playIntegrity),
            if (!scan.playRequested && scan.evidence.playIntegrity == EvidenceStatus.NOT_PROVIDED) {
                "Not requested: enter a Google Cloud project number to request a verdict"
            } else {
                "Google's verdict, bound to this scan's exact signed request"
            }),
        Row("Client checks", status(scan.evidence.clientSignals),
            "Root, hooking and scam-call checks reported by the app; they can be faked on a compromised phone"),
    )

    fun status(value: EvidenceStatus): Check.Status = when (value) {
        EvidenceStatus.VERIFIED -> Check.Status.PASS
        EvidenceStatus.SIGNED -> Check.Status.INFO
        EvidenceStatus.FAILED, EvidenceStatus.MALFORMED -> Check.Status.FAIL
        EvidenceStatus.UNAVAILABLE, EvidenceStatus.NOT_PROVIDED -> Check.Status.UNVERIFIED
    }

    fun explain(change: HistoryChange): String = when (change.code) {
        "FRESH_KEY_AUTHORIZED" -> "This scan's fresh key was signed for by your enrolled key. That links the evidence " +
            "to this enrollment; it does not prove it is the same physical phone."
        "KEY_ROTATED" -> "The enrolled key authorised a replacement key."
        "KEY_CONTINUITY_UNVERIFIED" -> "This evidence could not be linked to the enrolled key."
        "BOOT_EVIDENCE_CHANGED" -> "Verified boot state, bootloader lock or boot key (${change.field}) changed since the previous verified evidence."
        "ATTESTED_IDENTITY_CHANGED" -> "The hardware-attested ${change.field} changed."
        "PATCH_REGRESSION" -> "A security patch level (${change.field}) went backwards."
        "PATCH_COMPARISON_UNAVAILABLE" -> "The ${change.field} could not be compared (not attested or not parseable)."
        "BOOT_IMAGE_CHANGED" -> "The boot image changed. This is expected after a system update."
        else -> "${change.code} (${change.field})"
    }

    fun level(change: HistoryChange): Check.Status = if (change.level == "REVIEW") Check.Status.WARN else Check.Status.INFO

    fun time(millis: Long): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(Date(millis))
}
