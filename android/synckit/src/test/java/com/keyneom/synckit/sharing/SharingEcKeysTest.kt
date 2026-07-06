package com.keyneom.synckit.sharing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec

/**
 * SharingEcKeys signs via SHA256withECDSA plus DER<->P1363 conversion because
 * Android providers lack SHA256withECDSAinP1363Format. The desktop JVM running
 * these tests DOES have the P1363 algorithm, so we can assert byte-level
 * interoperability with the reference implementation (which matches WebCrypto).
 */
class SharingEcKeysTest {
    private fun keyPair() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    @Test
    fun `sign produces 64-byte P1363 signatures the JVM reference verifier accepts`() {
        val keys = keyPair()
        val message = "sync-kit p1363 parity".toByteArray()
        repeat(32) {
            val proof = SharingEcKeys.sign(keys.private as ECPrivateKey, message)
            assertEquals(64, proof.size)
            val reference = Signature.getInstance("SHA256withECDSAinP1363Format")
            reference.initVerify(keys.public)
            reference.update(message)
            assertTrue(reference.verify(proof))
        }
    }

    @Test
    fun `verify accepts signatures from the JVM reference P1363 signer`() {
        val keys = keyPair()
        val message = "webcrypto-style signature".toByteArray()
        repeat(32) {
            val reference = Signature.getInstance("SHA256withECDSAinP1363Format")
            reference.initSign(keys.private)
            reference.update(message)
            val proof = reference.sign()
            assertTrue(SharingEcKeys.verify(keys.public, message, proof))
        }
    }

    @Test
    fun `verify rejects tampered and malformed proofs without throwing`() {
        val keys = keyPair()
        val message = "tamper check".toByteArray()
        val proof = SharingEcKeys.sign(keys.private as ECPrivateKey, message)
        val tampered = proof.copyOf().also { it[10] = (it[10].toInt() xor 0x40).toByte() }
        assertFalse(SharingEcKeys.verify(keys.public, message, tampered))
        assertFalse(SharingEcKeys.verify(keys.public, "other message".toByteArray(), proof))
        assertFalse(SharingEcKeys.verify(keys.public, message, ByteArray(0)))
        assertFalse(SharingEcKeys.verify(keys.public, message, ByteArray(63)))
        assertFalse(SharingEcKeys.verify(keys.public, message, ByteArray(64)))
    }
}
