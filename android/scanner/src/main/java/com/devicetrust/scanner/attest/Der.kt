package com.devicetrust.scanner.attest

/** Minimal strict DER reader (port of service/device_trust/der.py). Malformed input throws [DerException]. */
class DerException(message: String) : Exception(message)

class Tlv(val cls: Int, val constructed: Boolean, val tag: Int, val value: ByteArray) {
    fun isUniversal(t: Int) = cls == CLASS_UNIVERSAL && tag == t

    fun children(): List<Tlv> {
        if (!constructed) throw DerException("primitive value has no children")
        return Der.readAll(value)
    }

    fun asLong(): Long {
        if (constructed || cls != CLASS_UNIVERSAL || (tag != TAG_INTEGER && tag != TAG_ENUMERATED)) {
            throw DerException("expected INTEGER/ENUMERATED")
        }
        if (value.isEmpty() || value.size > 8) throw DerException("unsupported INTEGER size")
        var out = if (value[0] < 0) -1L else 0L
        for (b in value) out = (out shl 8) or (b.toLong() and 0xff)
        return out
    }

    fun asInt(): Int = asLong().also { if (it !in Int.MIN_VALUE..Int.MAX_VALUE) throw DerException("INTEGER too large") }.toInt()

    fun asBool(): Boolean {
        if (constructed || !isUniversal(TAG_BOOLEAN) || value.size != 1) throw DerException("expected BOOLEAN")
        return when (value[0].toInt() and 0xff) {
            0x00 -> false
            0xff -> true
            else -> throw DerException("non-DER BOOLEAN")
        }
    }

    fun asBytes(): ByteArray {
        if (constructed || !isUniversal(TAG_OCTET_STRING)) throw DerException("expected OCTET STRING")
        return value
    }

    companion object {
        const val CLASS_UNIVERSAL = 0
        const val CLASS_CONTEXT = 2
        const val TAG_BOOLEAN = 1
        const val TAG_INTEGER = 2
        const val TAG_OCTET_STRING = 4
        const val TAG_NULL = 5
        const val TAG_ENUMERATED = 10
        const val TAG_SEQUENCE = 16
        const val TAG_SET = 17
    }
}

object Der {
    private fun readOne(data: ByteArray, start: Int): Pair<Tlv, Int> {
        var off = start
        val end = data.size
        if (off >= end) throw DerException("unexpected end of data")
        val first = data[off++].toInt() and 0xff
        val cls = first ushr 6
        val constructed = first and 0x20 != 0
        var tag = first and 0x1f
        if (tag == 0x1f) {
            tag = 0
            var i = 0
            while (true) {
                if (off >= end) throw DerException("truncated tag")
                val b = data[off++].toInt() and 0xff
                tag = (tag shl 7) or (b and 0x7f)
                if (b and 0x80 == 0) break
                if (++i >= 4) throw DerException("tag number too large")
            }
        }
        if (off >= end) throw DerException("truncated length")
        var length = data[off++].toInt() and 0xff
        if (length and 0x80 != 0) {
            val n = length and 0x7f
            if (n == 0 || n > 3) throw DerException("unsupported length encoding")
            if (off + n > end) throw DerException("truncated length")
            length = 0
            repeat(n) { length = (length shl 8) or (data[off++].toInt() and 0xff) }
        }
        if (length < 0 || off + length > end) throw DerException("value overruns buffer")
        return Tlv(cls, constructed, tag, data.copyOfRange(off, off + length)) to off + length
    }

    fun readAll(data: ByteArray): List<Tlv> {
        val out = mutableListOf<Tlv>()
        var off = 0
        while (off < data.size) {
            val (tlv, next) = readOne(data, off)
            out += tlv
            off = next
        }
        return out
    }

    fun readSingle(data: ByteArray): Tlv {
        val (tlv, next) = readOne(data, 0)
        if (next != data.size) throw DerException("trailing data after top-level value")
        return tlv
    }
}
