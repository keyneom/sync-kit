package com.keyneom.synckit.keys

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.security.MessageDigest

/** Strictly validates an ES256 registration response and returns its public JWK. */
fun extractEs256CredentialPublicKey(
    registrationResponseJson: String,
    expectedChallenge: String,
    rpId: String,
    allowedOrigins: Set<String>,
    requireUserVerification: Boolean = true,
): JsonObject {
    val registration = parseObject(registrationResponseJson, "WebAuthn registration")
    val response = registration["response"]?.jsonObject
        ?: compatibility("The WebAuthn registration response is missing.")
    val clientBytes = response.string("clientDataJSON")?.let(Base64Url::decode)
        ?: compatibility("The WebAuthn registration client data is missing.")
    val client = parseObject(clientBytes.toString(Charsets.UTF_8), "WebAuthn registration client data")
    if (
        client.string("type") != "webauthn.create" ||
        client.string("challenge") != expectedChallenge ||
        client.string("origin") !in allowedOrigins
    ) authorization("The WebAuthn registration context is invalid.")

    val attestation = response.string("attestationObject")?.let(Base64Url::decode)
        ?: compatibility("The WebAuthn attestation object is missing.")
    val attestationMap = CborReader(attestation).readCompleteMap()
    if (attestationMap["fmt"] != "none" || (attestationMap["attStmt"] as? Map<*, *>)?.isNotEmpty() != false) {
        compatibility("Only none-attestation passkey registrations are supported.")
    }
    val authData = attestationMap["authData"] as? ByteArray
        ?: compatibility("The WebAuthn attestation has no authenticator data.")
    if (authData.size < 55) compatibility("The WebAuthn registration authenticator data is truncated.")
    val rpHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray(Charsets.UTF_8))
    if (!MessageDigest.isEqual(authData.copyOfRange(0, 32), rpHash)) {
        authorization("The WebAuthn registration belongs to another relying party.")
    }
    val flags = authData[32].toInt() and 0xff
    if (flags and 0x01 == 0) authorization("The WebAuthn registration lacks user presence.")
    if (requireUserVerification && flags and 0x04 == 0) {
        authorization("The WebAuthn registration lacks user verification.")
    }
    if (flags and 0x40 == 0) compatibility("The WebAuthn registration has no attested credential data.")

    val credentialIdLength = ((authData[53].toInt() and 0xff) shl 8) or (authData[54].toInt() and 0xff)
    val credentialStart = 55
    val credentialEnd = credentialStart + credentialIdLength
    if (credentialIdLength == 0 || credentialEnd >= authData.size) {
        compatibility("The WebAuthn registration credential id is malformed.")
    }
    val credentialId = authData.copyOfRange(credentialStart, credentialEnd)
    val returnedId = registration.string("rawId") ?: registration.string("id")
        ?: compatibility("The WebAuthn registration has no credential id.")
    if (!MessageDigest.isEqual(credentialId, Base64Url.decode(returnedId))) {
        authorization("The WebAuthn registration credential id does not match its attestation.")
    }

    val cose = CborReader(authData, credentialEnd).readOneMap()
    if (cose[1L] != 2L || cose[3L] != -7L || cose[-1L] != 1L) {
        compatibility("The passkey public key must be an ES256 P-256 COSE key.")
    }
    val x = cose[-2L] as? ByteArray ?: compatibility("The passkey COSE key has no x coordinate.")
    val y = cose[-3L] as? ByteArray ?: compatibility("The passkey COSE key has no y coordinate.")
    if (x.size != 32 || y.size != 32) compatibility("The passkey COSE coordinates are malformed.")
    return buildJsonObject {
        put("kty", "EC")
        put("crv", "P-256")
        put("x", Base64Url.encode(x))
        put("y", Base64Url.encode(y))
        put("ext", true)
        put("key_ops", buildJsonArray { add(kotlinx.serialization.json.JsonPrimitive("verify")) })
    }
}

private class CborReader(
    private val bytes: ByteArray,
    private var offset: Int = 0,
) {
    fun readCompleteMap(): Map<Any, Any?> {
        val value = readValue(0) as? Map<Any, Any?> ?: compatibility("The CBOR value is not a map.")
        if (offset != bytes.size) compatibility("The CBOR value has trailing bytes.")
        return value
    }

    fun readOneMap(): Map<Any, Any?> =
        readValue(0) as? Map<Any, Any?> ?: compatibility("The COSE key is not a map.")

    private fun readValue(depth: Int): Any? {
        if (depth > 12 || offset >= bytes.size) compatibility("The CBOR value is malformed.")
        val initial = bytes[offset++].toInt() and 0xff
        val major = initial ushr 5
        val info = initial and 0x1f
        val argument = readArgument(info)
        return when (major) {
            0 -> argument
            1 -> -1L - argument
            2 -> readBytes(argument)
            3 -> readBytes(argument).toString(Charsets.UTF_8)
            4 -> List(checkedLength(argument)) { readValue(depth + 1) }
            5 -> buildMap {
                repeat(checkedLength(argument)) {
                    val key = readValue(depth + 1)
                        ?: compatibility("CBOR map keys must not be null.")
                    put(key, readValue(depth + 1))
                }
            }
            6 -> readValue(depth + 1)
            7 -> when (info) {
                20 -> false
                21 -> true
                22, 23 -> null
                else -> compatibility("The CBOR simple value is unsupported.")
            }
            else -> compatibility("The CBOR major type is unsupported.")
        }
    }

    private fun readArgument(info: Int): Long = when {
        info < 24 -> info.toLong()
        info == 24 -> readUnsigned(1)
        info == 25 -> readUnsigned(2)
        info == 26 -> readUnsigned(4)
        info == 27 -> readUnsigned(8)
        else -> compatibility("Indefinite-length CBOR is unsupported.")
    }

    private fun readUnsigned(length: Int): Long {
        if (offset + length > bytes.size) compatibility("The CBOR value is truncated.")
        var result = 0L
        repeat(length) { result = (result shl 8) or (bytes[offset++].toLong() and 0xff) }
        if (result < 0) compatibility("The CBOR integer is too large.")
        return result
    }

    private fun readBytes(length: Long): ByteArray {
        val size = checkedLength(length)
        if (offset + size > bytes.size) compatibility("The CBOR byte string is truncated.")
        return bytes.copyOfRange(offset, offset + size).also { offset += size }
    }

    private fun checkedLength(value: Long): Int {
        if (value < 0 || value > 1_048_576) compatibility("The CBOR value is too large.")
        return value.toInt()
    }
}

private fun parseObject(value: String, label: String): JsonObject = try {
    SyncKitJson.instance.parseToJsonElement(value).jsonObject
} catch (error: Exception) {
    throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, "The $label is invalid.", error)
}

private fun JsonObject.string(name: String): String? = this[name]?.jsonPrimitive?.contentOrNull
private fun authorization(message: String): Nothing = throw SyncKitError(SyncKitErrorCode.AUTHORIZATION, message)
private fun compatibility(message: String): Nothing = throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, message)
