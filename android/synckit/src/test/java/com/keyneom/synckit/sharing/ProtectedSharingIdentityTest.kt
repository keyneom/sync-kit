package com.keyneom.synckit.sharing

import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.crypto.V1KeyMetadata
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectedSharingIdentityTest {
    /** A ProtectedSharingIdentityV1 wrapped by WebCrypto must unlock on Android. */
    @Test
    fun unlocksWebCryptoWrappedIdentity() {
        val fixtureText = javaClass.classLoader
            ?.getResourceAsStream("sharing-v1/protected-identity.json")
            ?.use { it.readBytes().toString(Charsets.UTF_8) }
            ?: error("Missing sharing-v1/protected-identity.json test resource.")
        val root = SyncKitJson.instance.parseToJsonElement(fixtureText).jsonObject
        val wrappingKey = Base64Url.decode(root["wrappingKey"]!!.jsonPrimitive.content)
        val record = SyncKitJson.instance.decodeFromJsonElement(
            ProtectedSharingIdentityV1.serializer(),
            root["record"]!!.jsonObject,
        )
        val expectedKeyId = root["expected"]!!.jsonObject["keyId"]!!.jsonPrimitive.content

        val identity = ProtectedSharingIdentityCrypto.unlock(
            ProtectedSharingIdentityCrypto.parse(record),
            wrappingKey,
        )

        assertEquals(expectedKeyId, identity.publicKey.keyId)
        assertUsableIdentity(identity)
    }

    /** Android-wrapped identity must round-trip through unlock (same wrap format). */
    @Test
    fun roundTripsAndroidWrappedIdentity() {
        val wrappingKey = ByteArray(32) { it.toByte() }
        val metadata = V1KeyMetadata(
            credentialId = Base64Url.encode(ByteArray(16) { (it + 3).toByte() }),
            rpId = "keyneom.github.io",
            prfInput = ByteArray(32) { (it + 7).toByte() },
            kdfSalt = ByteArray(32) { (it + 11).toByte() },
        )
        val wrapped = ProtectedSharingIdentityCrypto.create("easy-bc", metadata, wrappingKey)
        val unlocked = ProtectedSharingIdentityCrypto.unlock(wrapped.record, wrappingKey)

        assertEquals(wrapped.identity.publicKey.keyId, unlocked.publicKey.keyId)
        assertEquals(metadata.credentialId, wrapped.record.credentialId)
        assertUsableIdentity(unlocked)
    }

    /** The wrong wrapping key must fail authentication, not silently succeed. */
    @Test
    fun rejectsWrongWrappingKey() {
        val wrappingKey = ByteArray(32) { it.toByte() }
        val metadata = V1KeyMetadata(
            credentialId = Base64Url.encode(ByteArray(16) { it.toByte() }),
            rpId = "keyneom.github.io",
            prfInput = ByteArray(32) { it.toByte() },
            kdfSalt = ByteArray(32) { (it + 1).toByte() },
        )
        val wrapped = ProtectedSharingIdentityCrypto.create("easy-bc", metadata, wrappingKey)
        val wrongKey = wrappingKey.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val failed = runCatching {
            ProtectedSharingIdentityCrypto.unlock(wrapped.record, wrongKey)
        }
        assertTrue("Expected unlock with the wrong key to fail", failed.isFailure)
    }

    /** Proves both imported private keys correspond to the record's public keys. */
    private fun assertUsableIdentity(identity: SharingIdentity) {
        val message = "protected-identity-parity".toByteArray(Charsets.UTF_8)
        val signature = SharingEcKeys.sign(identity.signingPrivateKey, message)
        assertTrue(
            "Signature must verify against the record's signing public key",
            SharingEcKeys.verify(
                SharingEcKeys.signingPublicKey(identity.publicKey),
                message,
                signature,
            ),
        )
        // ECDH from the imported private key must agree with ECDH from a peer
        // using the record's public key — i.e. the private key matches the record.
        val peer = SharingEcKeys.generateIdentity()
        val fromOurPrivate = SharingEcKeys.ecdh(
            identity.encryptionPrivateKey,
            SharingEcKeys.encryptionPublicKey(peer.publicKey),
        )
        val fromPeerPrivate = SharingEcKeys.ecdh(
            peer.encryptionPrivateKey,
            SharingEcKeys.encryptionPublicKey(identity.publicKey),
        )
        assertArrayEquals(fromOurPrivate, fromPeerPrivate)
    }
}
