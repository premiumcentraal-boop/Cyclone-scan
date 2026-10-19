package com.devicetrust.scanner

import com.devicetrust.scanner.attest.RevocationCopy
import com.devicetrust.scanner.attest.RevocationResolver
import com.devicetrust.scanner.attest.RevocationSource
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RevocationResolverTest {
    private val now = 1_000_000_000L
    private val day = RevocationResolver.MAX_CACHE_AGE_MS

    @Test
    fun retriesTransientFailuresThenSucceeds() {
        var calls = 0
        val sleeps = mutableListOf<Long>()
        val result = RevocationResolver.withRetry(listOf(400L, 1200L), { sleeps += it }) {
            calls++
            if (calls < 3) throw IOException("no such host") else setOf("a")
        }
        assertEquals(setOf("a"), result.getOrNull())
        assertEquals(3, calls)
        assertEquals(listOf(400L, 1200L), sleeps)
    }

    @Test
    fun givesUpAfterTheLastAttempt() {
        var calls = 0
        val result = RevocationResolver.withRetry(listOf(400L, 1200L), { }) {
            calls++
            throw IOException("timeout")
        }
        assertTrue(result.isFailure)
        assertEquals(3, calls)
    }

    @Test
    fun doesNotRetryErrorsThatAreNotNetworkFailures() {
        var calls = 0
        val result = RevocationResolver.withRetry(listOf(400L), { }) {
            calls++
            throw IllegalStateException("malformed list")
        }
        assertTrue(result.isFailure)
        assertEquals(1, calls)
    }

    @Test
    fun liveListWinsOverACopy() {
        val res = RevocationResolver.resolve(Result.success(setOf("a")), RevocationCopy(setOf("b"), now), now)
        assertEquals(RevocationSource.LIVE, res.source)
        assertEquals(setOf("a"), res.serials)
        assertNull(res.liveError)
    }

    @Test
    fun freshCopyIsUsedWhenTheLiveDownloadFails() {
        val res = RevocationResolver.resolve(
            Result.failure(IOException("dns")), RevocationCopy(setOf("b"), now - 1000), now,
        )
        assertEquals(RevocationSource.CACHED, res.source)
        assertEquals(setOf("b"), res.serials)
        assertEquals(1000L, res.cachedAgeMs)
        assertNotNull(res.liveError)
    }

    @Test
    fun staleCopyIsNotUsed() {
        val res = RevocationResolver.resolve(
            Result.failure(IOException("dns")), RevocationCopy(setOf("b"), now - day - 1), now,
        )
        assertEquals(RevocationSource.NONE, res.source)
        assertNull(res.serials)
    }

    @Test
    fun withoutAListOrACopyTheCheckStaysUnestablished() {
        val res = RevocationResolver.resolve(Result.failure(IOException("dns")), null, now)
        assertEquals(RevocationSource.NONE, res.source)
        assertNull(res.serials)
    }

    @Test
    fun aCopyFromTheFutureIsNotUsed() {
        val res = RevocationResolver.resolve(
            Result.failure(IOException("dns")), RevocationCopy(setOf("b"), now + 5), now,
        )
        assertEquals(RevocationSource.NONE, res.source)
    }
}
