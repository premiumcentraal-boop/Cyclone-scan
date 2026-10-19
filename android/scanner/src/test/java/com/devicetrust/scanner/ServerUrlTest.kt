package com.devicetrust.scanner

import com.devicetrust.scanner.ui.ServerUrl
import org.junit.Assert.assertEquals
import org.junit.Test

class ServerUrlTest {
    @Test
    fun theOldPlaceholderAddressIsNotPrefilled() {
        assertEquals("", ServerUrl.fromStored(ServerUrl.LEGACY_PLACEHOLDER))
    }

    @Test
    fun noStoredValueIsEmpty() {
        assertEquals("", ServerUrl.fromStored(null))
    }

    @Test
    fun aRealAddressIsKept() {
        assertEquals("http://10.0.0.5:8080", ServerUrl.fromStored("http://10.0.0.5:8080"))
    }
}
