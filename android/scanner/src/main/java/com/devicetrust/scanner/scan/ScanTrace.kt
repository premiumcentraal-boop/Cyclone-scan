package com.devicetrust.scanner.scan

import org.json.JSONArray
import org.json.JSONObject

/**
 * Run 31: what happened during one local scan, phase by phase, so a debug report can say
 * not only *that* something could not be scanned but *why* (the exception class and a
 * sanitized message). Thread-confined to the scan; read after it finishes or fails.
 */
class ScanTrace(private val clock: () -> Long = System::currentTimeMillis) {
    enum class Outcome { OK, FAILED, DEGRADED, SKIPPED }

    data class Phase(
        val id: String,
        val outcome: Outcome,
        val durationMs: Long,
        val detail: String? = null,
        val errorType: String? = null,
        val errorMessage: String? = null,
    )

    private val phases = mutableListOf<Phase>()
    val all: List<Phase> get() = phases.toList()

    /** Runs [block] as phase [id]; a thrown exception is recorded and re-thrown. */
    fun <T> phase(id: String, block: () -> T): T {
        val start = clock()
        return try {
            block().also { phases += Phase(id, Outcome.OK, clock() - start) }
        } catch (e: Throwable) {
            phases += failed(id, clock() - start, e)
            throw e
        }
    }

    /** Runs [block]; an exception is recorded and turned into null (the scan continues degraded). */
    fun <T> optional(id: String, block: () -> T?): T? {
        val start = clock()
        return try {
            block().also {
                phases += Phase(id, if (it == null) Outcome.DEGRADED else Outcome.OK, clock() - start,
                    if (it == null) "returned no result" else null)
            }
        } catch (e: Exception) {
            phases += failed(id, clock() - start, e)
            null
        }
    }

    /** Records an outcome that was decided elsewhere (e.g. a Result with its own error). */
    fun record(id: String, outcome: Outcome, durationMs: Long, detail: String? = null, error: Throwable? = null) {
        phases += Phase(id, outcome, durationMs, detail?.let { sanitize(it) },
            error?.let { typeName(it) }, error?.let { messageOf(it) })
    }

    private fun failed(id: String, durationMs: Long, e: Throwable) =
        Phase(id, Outcome.FAILED, durationMs, null, typeName(e), messageOf(e))

    fun toJson(): JSONArray = JSONArray(phases.map { p ->
        JSONObject().put("phase", p.id).put("outcome", p.outcome.name).put("durationMs", p.durationMs)
            .put("detail", p.detail ?: JSONObject.NULL)
            .put("errorType", p.errorType ?: JSONObject.NULL)
            .put("errorMessage", p.errorMessage ?: JSONObject.NULL)
    })

    companion object {
        const val MAX_MESSAGE = 240
        private val PATH = Regex("""(?:/[\w.@+\-]+){2,}/?""")
        private val URL = Regex("""https?://\S+""")
        private val HEX_ID = Regex("""\b[0-9a-fA-F]{16,}\b""")

        fun typeName(e: Throwable): String = e.javaClass.name

        /** Message plus causes, sanitized: no file paths, URLs or long hex identifiers. */
        fun messageOf(e: Throwable): String? {
            val parts = generateSequence(e) { it.cause.takeIf { c -> c !== it } }.take(4)
                .mapNotNull { t -> t.message?.let { "${t.javaClass.simpleName}: $it" } }
                .toList()
            return parts.joinToString(" <- ").takeIf { it.isNotEmpty() }?.let(::sanitize)
        }

        fun sanitize(text: String): String = text
            .replace(URL, "<url>")
            .replace(PATH, "<path>")
            .replace(HEX_ID, "<hex>")
            .replace(Regex("\\s+"), " ")
            .trim()
            .take(MAX_MESSAGE)
    }
}
