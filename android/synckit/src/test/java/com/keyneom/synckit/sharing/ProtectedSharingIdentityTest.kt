package com.keyneom.synckit.sharing

import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.crypto.V1KeyMetadata
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
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

    @Test
    fun replacementCredentialPreservesSharingKeyId() {
        val oldKey = ByteArray(32) { it.toByte() }
        val oldMetadata = V1KeyMetadata(
            "old-credential",
            "example.test",
            ByteArray(32) { 1 },
            ByteArray(32) { 2 },
        )
        val original = ProtectedSharingIdentityCrypto.create("fixture-app", oldMetadata, oldKey)
        val credentialJwk = buildJsonObject {
            put("kty", "EC")
            put("crv", "P-256")
            put("x", Base64Url.encode(ByteArray(32) { 3 }))
            put("y", Base64Url.encode(ByteArray(32) { 4 }))
        }
        val replacementKey = ByteArray(32) { (it + 7).toByte() }
        val replacementMetadata = V1KeyMetadata(
            "replacement-credential",
            "example.test",
            ByteArray(32) { 5 },
            ByteArray(32) { 6 },
            credentialJwk,
        )

        val replacement = ProtectedSharingIdentityCrypto.rewrapWithReplacementCredential(
            original.record,
            oldKey,
            replacementMetadata,
            replacementKey,
        )

        assertEquals(original.record.publicKey.keyId, replacement.record.publicKey.keyId)
        assertEquals("replacement-credential", replacement.record.credentialId)
        assertEquals(credentialJwk, ProtectedSharingIdentityCrypto.accountBindingCredential(replacement.record).credentialPublicKey)
        assertEquals(
            original.record.publicKey.keyId,
            ProtectedSharingIdentityCrypto.unlock(replacement.record, replacementKey).publicKey.keyId,
        )
        assertEquals(
            original.record.publicKey.keyId,
            ProtectedSharingIdentityCrypto.unlock(original.record, oldKey).publicKey.keyId,
        )
    }

    @Test
    fun failedReplacementLeavesOriginalIdentityUsable() {
        val oldKey = ByteArray(32) { it.toByte() }
        val original = ProtectedSharingIdentityCrypto.create(
            "fixture-app",
            V1KeyMetadata("old", "example.test", ByteArray(32) { 1 }, ByteArray(32) { 2 }),
            oldKey,
        )
        val failed = runCatching {
            ProtectedSharingIdentityCrypto.rewrapWithReplacementCredential(
                original.record,
                oldKey,
                V1KeyMetadata("new", "example.test", ByteArray(32) { 3 }, ByteArray(32) { 4 }),
                ByteArray(32) { 5 },
            )
        }
        assertTrue(failed.isFailure)
        assertEquals(
            original.record.publicKey.keyId,
            ProtectedSharingIdentityCrypto.unlock(original.record, oldKey).publicKey.keyId,
        )
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
