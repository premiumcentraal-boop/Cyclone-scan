package com.devicetrust.scanner.attest

import com.devicetrust.scanner.attest.Tlv.Companion.CLASS_CONTEXT
import com.devicetrust.scanner.attest.Tlv.Companion.TAG_NULL
import com.devicetrust.scanner.attest.Tlv.Companion.TAG_SEQUENCE
import com.devicetrust.scanner.attest.Tlv.Companion.TAG_SET

/**
 * Android key attestation extension (KeyDescription), port of
 * service/device_trust/key_description.py. Serial/IMEI/MEID are never decoded.
 */
const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

enum class SecurityLevel { SOFTWARE, TRUSTED_ENVIRONMENT, STRONG_BOX }
enum class VerifiedBootState { VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED }

const val AUTH_PASSWORD = 1
const val AUTH_BIOMETRIC = 2

class RootOfTrust(
    val verifiedBootKey: ByteArray,
    val deviceLocked: Boolean,
    val verifiedBootState: VerifiedBootState,
)

class AppId(val packageNames: List<String>, val signatureDigests: List<ByteArray>)

class AuthorizationList(
    val origin: Int? = null,
    val noAuthRequired: Boolean = false,
    val userAuthType: Int? = null,
    val authTimeout: Long? = null,
    val rootOfTrust: RootOfTrust? = null,
    val osVersion: Int? = null,
    val osPatchLevel: Int? = null,
    val vendorPatchLevel: Int? = null,
    val bootPatchLevel: Int? = null,
    val appId: AppId? = null,
    val attestedIds: Map<String, String> = emptyMap(),
)

class KeyDescription(
    val attestationVersion: Int,
    val attestationSecurityLevel: SecurityLevel,
    val keyMintVersion: Int,
    val keyMintSecurityLevel: SecurityLevel,
    val challenge: ByteArray,
    val softwareEnforced: AuthorizationList,
    val hardwareEnforced: AuthorizationList,
)

object KeyDescriptionParser {
    private val ID_TAGS = mapOf(710 to "brand", 711 to "device", 712 to "product", 716 to "manufacturer", 717 to "model")

    fun parse(extensionValue: ByteArray): KeyDescription {
        val seq = Der.readSingle(extensionValue)
        if (!seq.isUniversal(TAG_SEQUENCE)) throw DerException("KeyDescription must be a SEQUENCE")
        val f = seq.children()
        if (f.size != 8) throw DerException("KeyDescription must have 8 fields, got ${f.size}")
        return KeyDescription(
            attestationVersion = f[0].asInt(),
            attestationSecurityLevel = level(f[1].asInt()),
            keyMintVersion = f[2].asInt(),
            keyMintSecurityLevel = level(f[3].asInt()),
            challenge = f[4].asBytes(),
            softwareEnforced = authList(f[6]),
            hardwareEnforced = authList(f[7]),
        )
    }

    private fun level(v: Int) = SecurityLevel.entries.getOrNull(v) ?: throw DerException("bad security level $v")

    private fun inner(t: Tlv): Tlv {
        if (!t.constructed) throw DerException("context tag [${t.tag}] must be explicit")
        return Der.readSingle(t.value)
    }

    private fun authList(t: Tlv): AuthorizationList {
        if (!t.isUniversal(TAG_SEQUENCE)) throw DerException("AuthorizationList must be a SEQUENCE")
        var origin: Int? = null
        var noAuth = false
        var userAuth: Int? = null
        var timeout: Long? = null
        var rot: RootOfTrust? = null
        var osVersion: Int? = null
        var osPatch: Int? = null
        var vendorPatch: Int? = null
        var bootPatch: Int? = null
        var appId: AppId? = null
        val ids = mutableMapOf<String, String>()
        val seen = mutableSetOf<Int>()
        for (item in t.children()) {
            if (item.cls != CLASS_CONTEXT) throw DerException("entries must be context-tagged")
            if (!seen.add(item.tag)) throw DerException("duplicate tag [${item.tag}]")
            when (item.tag) {
                503 -> {
                    val n = inner(item)
                    if (!n.isUniversal(TAG_NULL) || n.value.isNotEmpty()) throw DerException("noAuthRequired must be NULL")
                    noAuth = true
                }
                504 -> userAuth = inner(item).asInt()
                505 -> timeout = inner(item).asLong()
                702 -> origin = inner(item).asInt()
                704 -> rot = rootOfTrust(inner(item))
                705 -> osVersion = inner(item).asInt()
                706 -> osPatch = inner(item).asInt()
                709 -> appId = appId(inner(item).asBytes())
                718 -> vendorPatch = inner(item).asInt()
                719 -> bootPatch = inner(item).asInt()
                in ID_TAGS -> ids[ID_TAGS.getValue(item.tag)] = String(inner(item).asBytes(), Charsets.UTF_8)
                else -> Unit // includes serial/IMEI/MEID: intentionally skipped
            }
        }
        return AuthorizationList(origin, noAuth, userAuth, timeout, rot, osVersion, osPatch, vendorPatch, bootPatch, appId, ids)
    }

    private fun rootOfTrust(t: Tlv): RootOfTrust {
        if (!t.isUniversal(TAG_SEQUENCE)) throw DerException("RootOfTrust must be a SEQUENCE")
        val f = t.children()
        if (f.size < 3) throw DerException("RootOfTrust too short")
        val state = VerifiedBootState.entries.getOrNull(f[2].asInt()) ?: throw DerException("bad boot state")
        return RootOfTrust(f[0].asBytes(), f[1].asBool(), state)
    }

    private fun appId(raw: ByteArray): AppId {
        val seq = Der.readSingle(raw)
        val f = seq.children()
        if (f.size != 2 || !f.all { it.isUniversal(TAG_SET) }) throw DerException("bad AttestationApplicationId")
        val pkgs = f[0].children().map { String(it.children().first().asBytes(), Charsets.UTF_8) }
        val digests = f[1].children().map { it.asBytes() }
        return AppId(pkgs, digests)
    }
}
