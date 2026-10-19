package com.devicetrust.scanner

import com.devicetrust.scanner.scan.ReportCoverage
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReasonTextTest {
    @Test
    fun aMissingNativeReasonPointsAtTheNativeReview() {
        val text = ReportCoverage.reasonText(null)
        assertTrue(text.contains("Run 27 native review"))
        assertFalse(text == "no reason reported")
    }

    @Test
    fun scopeLimitedSaysThatAbsenceProvesNothing() {
        val text = ReportCoverage.reasonText("SCOPE_LIMITED")
        assertTrue(text.contains("own process"))
        assertTrue(text.contains("proves nothing"))
    }

    @Test
    fun unknownCodesStillGetTheGenericText() {
        assertTrue(ReportCoverage.reasonText("SOMETHING_NEW") == "no reason reported")
    }
}
