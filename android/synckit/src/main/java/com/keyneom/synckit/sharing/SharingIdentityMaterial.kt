package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec

/**
 * The one private-key byte format shared by passkey-protected sharing
 * identities and recovery keys: `[4-byte big-endian length of enc][enc
 * PKCS#8][sig PKCS#8]`, matching the web package.
 */
internal object SharingIdentityMaterial {
    private val keyFactory: KeyFactory by lazy { KeyFactory.getInstance("EC") }

    /** The identity's private keys, packed. The caller zeroes the result. */
    fun pack(identity: SharingIdentity): ByteArray =
        packPrivateKeys(identity.encryptionPrivateKey.encoded, identity.signingPrivateKey.encoded)

    /** Imports packed private keys and confirms they match [publicKey]. The caller zeroes [packed]. */
    fun importIdentity(publicKey: SharingPublicKeyV1, packed: ByteArray): SharingIdentity {
        val (encryptionPrivate, signingPrivate) = unpackPrivateKeys(packed)
        try {
            val identity = SharingIdentity(
                publicKey = publicKey,
                encryptionPrivateKey = importPrivateKey(encryptionPrivate),
                signingPrivateKey = importPrivateKey(signingPrivate),
            )
            val expected = SharingEcKeys.createSharingPublicKeyV1(
                publicKey.encryptionPublicKey,
                publicKey.signingPublicKey,
            )
            if (expected.keyId != publicKey.keyId) {
                throw SyncKitError(
                    SyncKitErrorCode.KEY,
                    "The protected sharing identity public-key fingerprint is invalid.",
                )
            }
            return identity
        } finally {
            encryptionPrivate.fill(0)
            signingPrivate.fill(0)
        }
    }

    fun packPrivateKeys(enc: ByteArray, sig: ByteArray): ByteArray {
        val packed = ByteArray(4 + enc.size + sig.size)
        packed[0] = (enc.size ushr 24).toByte()
        packed[1] = (enc.size ushr 16).toByte()
        packed[2] = (enc.size ushr 8).toByte()
        packed[3] = enc.size.toByte()
        System.arraycopy(enc, 0, packed, 4, enc.size)
        System.arraycopy(sig, 0, packed, 4 + enc.size, sig.size)
        return packed
    }

    fun unpackPrivateKeys(packed: ByteArray): Pair<ByteArray, ByteArray> {
        if (packed.size < 5) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "Protected sharing private-key material is malformed.",
            )
        }
        val encLength =
            ((packed[0].toInt() and 0xff) shl 24) or
                ((packed[1].toInt() and 0xff) shl 16) or
                ((packed[2].toInt() and 0xff) shl 8) or
                (packed[3].toInt() and 0xff)
        if (encLength == 0 || 4 + encLength >= packed.size) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "Protected sharing private-key material is malformed.",
            )
        }
        return packed.copyOfRange(4, 4 + encLength) to
            packed.copyOfRange(4 + encLength, packed.size)
    }

    private fun importPrivateKey(pkcs8: ByteArray): ECPrivateKey =
        keyFactory.generatePrivate(PKCS8EncodedKeySpec(pkcs8)) as ECPrivateKey
}
