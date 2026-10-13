package com.devicetrust.client

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityException
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import com.google.android.play.core.integrity.model.StandardIntegrityErrorCode
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.tasks.await

/** Supplies a Play Integrity token bound to a request hash, or null if unavailable. */
fun interface IntegrityTokenSource {
    suspend fun token(requestHash: String): String?
}

/**
 * Play Integrity standard requests. Returns null when Play services are missing
 * or the API fails (e.g. Huawei, GrapheneOS without sandboxed Play): the server
 * policy decides whether a missing verdict is acceptable.
 *
 * @param cloudProjectNumber the Google Cloud project linked in Play Console.
 */
class PlayIntegrityTokenSource(
    context: Context,
    private val cloudProjectNumber: Long,
) : IntegrityTokenSource {
    private val manager = IntegrityManagerFactory.createStandard(context.applicationContext)
    private val mutex = Mutex()
    private var provider: StandardIntegrityTokenProvider? = null

    /** Optional warm-up (e.g. at app start) so the first enrollment is faster. */
    suspend fun prepare() {
        runCatching { providerOrPrepare() }
    }

    override suspend fun token(requestHash: String): String? = try {
        request(requestHash)
    } catch (e: StandardIntegrityException) {
        if (e.errorCode == StandardIntegrityErrorCode.INTEGRITY_TOKEN_PROVIDER_INVALID) {
            mutex.withLock { provider = null }
            runCatching { request(requestHash) }.getOrNull()
        } else {
            null
        }
    } catch (e: Exception) {
        if (e is kotlinx.coroutines.CancellationException) throw e
        null
    }

    private suspend fun request(requestHash: String): String {
        val tokenRequest = StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build()
        return providerOrPrepare().request(tokenRequest).await().token()
    }

    private suspend fun providerOrPrepare(): StandardIntegrityTokenProvider = mutex.withLock {
        provider ?: manager.prepareIntegrityToken(
            PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(cloudProjectNumber).build(),
        ).await().also { provider = it }
    }
}
