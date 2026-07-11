package com.keyneom.synckit.keys

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey

class WebAuthnRegistrationTest {
    @Test
    fun extractsValidatedCoseEc2PublicKey() {
        val challenge = Base64Url.encode(ByteArray(32) { 7 })
        val rpId = "example.test"
        val origin = "android:apk-key-hash:release"
        val credentialId = "credential-id".toByteArray()
        val keys = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val publicKey = keys.public as ECPublicKey
        val x = fixed32(publicKey.w.affineX.toByteArray())
        val y = fixed32(publicKey.w.affineY.toByteArray())
        val cose = cborMap(
            cborInt(1) to cborInt(2),
            cborInt(3) to cborInt(-7),
            cborInt(-1) to cborInt(1),
            cborInt(-2) to cborBytes(x),
            cborInt(-3) to cborBytes(y),
        )
        val authData = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray()) +
            byteArrayOf(0x45, 0, 0, 0, 0) +
            ByteArray(16) +
            byteArrayOf(0, credentialId.size.toByte()) +
            credentialId + cose
        val attestation = cborMap(
            cborText("fmt") to cborText("none"),
            cborText("authData") to cborBytes(authData),
            cborText("attStmt") to cborMap(),
        )
        val clientData = """{"type":"webauthn.create","challenge":"$challenge","origin":"$origin"}""".toByteArray()
        val registration = buildJsonObject {
            put("id", Base64Url.encode(credentialId))
            put("rawId", Base64Url.encode(credentialId))
            put("response", buildJsonObject {
                put("clientDataJSON", Base64Url.encode(clientData))
                put("attestationObject", Base64Url.encode(attestation))
            })
        }
        val json = SyncKitJson.instance.encodeToString(JsonObject.serializer(), registration)

        val jwk = extractEs256CredentialPublicKey(json, challenge, rpId, setOf(origin))
        assertEquals("EC", jwk["kty"]!!.toString().trim('"'))
        assertEquals(Base64Url.encode(x), jwk["x"]!!.toString().trim('"'))
        assertEquals(Base64Url.encode(y), jwk["y"]!!.toString().trim('"'))

        val error = runCatching {
            extractEs256CredentialPublicKey(json, challenge, "other.test", setOf(origin))
        }.exceptionOrNull() as SyncKitError
        assertEquals(SyncKitErrorCode.AUTHORIZATION, error.code)
    }

    private fun fixed32(value: ByteArray): ByteArray {
        val unsigned = if (value.size > 1 && value[0] == 0.toByte()) value.copyOfRange(1, value.size) else value
        return if (unsigned.size == 32) unsigned else ByteArray(32 - unsigned.size) + unsigned
    }

    private fun cborMap(vararg entries: Pair<ByteArray, ByteArray>): ByteArray =
        cborHeader(5, entries.size.toLong()) + entries.flatMap { (key, value) -> (key + value).asIterable() }.toByteArray()

    private fun cborBytes(value: ByteArray): ByteArray = cborHeader(2, value.size.toLong()) + value
    private fun cborText(value: String): ByteArray = value.toByteArray().let { cborHeader(3, it.size.toLong()) + it }
    private fun cborInt(value: Long): ByteArray =
        if (value >= 0) cborHeader(0, value) else cborHeader(1, -1 - value)

    private fun cborHeader(major: Int, value: Long): ByteArray = when {
        value < 24 -> byteArrayOf(((major shl 5) or value.toInt()).toByte())
        value <= 0xff -> byteArrayOf(((major shl 5) or 24).toByte(), value.toByte())
        value <= 0xffff -> byteArrayOf(
            ((major shl 5) or 25).toByte(),
            (value ushr 8).toByte(),
            value.toByte(),
        )
        else -> error("test CBOR length is too large")
    }
}
