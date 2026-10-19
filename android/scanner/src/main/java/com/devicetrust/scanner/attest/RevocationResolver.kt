package com.devicetrust.scanner.attest

import java.io.IOException

/** Where the revocation list used for a scan came from. */
enum class RevocationSource { LIVE, CACHED, NONE }

/** A revocation list saved after a successful live download (public Google data, no identifiers). */
data class RevocationCopy(val serials: Set<String>, val savedAtMs: Long)

data class RevocationResolution(
    val serials: Set<String>?,
    val source: RevocationSource,
    /** Age of the saved copy when [source] is CACHED. */
    val cachedAgeMs: Long?,
    /** Why the live download failed, when it did. */
    val liveError: Throwable?,
)

/**
 * Turns a revocation download into the list a scan uses. A network failure is retried a
 * few times, because a phone that has just changed network often fails the first lookup.
 * When every attempt fails, a copy saved within [MAX_CACHE_AGE_MS] is used and labelled as
 * cached. Without a live list or a recent copy, revocation stays unestablished, as before.
 */
object RevocationResolver {
    const val MAX_CACHE_AGE_MS: Long = 24L * 60 * 60 * 1000
    val RETRY_DELAYS_MS: List<Long> = listOf(400L, 1200L)

    /** Only network-level failures are retried; a malformed list is not going to change. */
    fun isTransient(t: Throwable?): Boolean = t is IOException

    /** Calls [attempt] once, then again after each delay while the failure is transient. */
    fun <T> withRetry(
        delaysMs: List<Long> = RETRY_DELAYS_MS,
        sleep: (Long) -> Unit = { Thread.sleep(it) },
        attempt: () -> T,
    ): Result<T> {
        var last: Throwable? = null
        for (i in 0..delaysMs.size) {
            val result = runCatching(attempt)
            if (result.isSuccess) return result
            last = result.exceptionOrNull()
            if (!isTransient(last) || i == delaysMs.size) break
            sleep(delaysMs[i])
        }
        return Result.failure(last ?: IllegalStateException("no attempt ran"))
    }

    fun resolve(live: Result<Set<String>>, cached: RevocationCopy?, nowMs: Long): RevocationResolution {
        live.getOrNull()?.let { return RevocationResolution(it, RevocationSource.LIVE, null, null) }
        val error = live.exceptionOrNull()
        if (cached != null) {
            val age = nowMs - cached.savedAtMs
            if (age in 0..MAX_CACHE_AGE_MS) {
                return RevocationResolution(cached.serials, RevocationSource.CACHED, age, error)
            }
        }
        return RevocationResolution(null, RevocationSource.NONE, null, error)
    }
}
