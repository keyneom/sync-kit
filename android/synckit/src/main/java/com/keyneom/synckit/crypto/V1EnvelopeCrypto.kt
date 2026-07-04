package com.keyneom.synckit.crypto

import com.keyneom.synckit.core.SyncCodec
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class V1EnvelopeCrypto<T>(
    private val profile: V1CompatibilityProfile,
    private val codec: SyncCodec<T>,
) {
    private val aad = profile.aad.toByteArray(Charsets.UTF_8)
    private val hkdfInfo = profile.hkdfInfo.toByteArray(Charsets.UTF_8)
    private val random = SecureRandom()

    fun randomBytes(length: Int): ByteArray = ByteArray(length).also(random::nextBytes)

    fun deriveContentKey(inputKeyMaterial: ByteArray, salt: ByteArray): ByteArray {
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(salt, "HmacSHA256"))
        val pseudoRandomKey = extract.doFinal(inputKeyMaterial)
        val expand = Mac.getInstance("HmacSHA256")
        expand.init(SecretKeySpec(pseudoRandomKey, "HmacSHA256"))
        expand.update(hkdfInfo)
        expand.update(1)
        val output = expand.doFinal().copyOf(32)
        pseudoRandomKey.fill(0)
        return output
    }

    fun encrypt(value: T, contentKey: ByteArray, metadata: V1KeyMetadata): SyncEnvelopeV1 =
        encryptWithNonce(value, contentKey, metadata, randomBytes(profile.nonceBytes))

    internal fun encryptWithNonce(
        value: T,
        contentKey: ByteArray,
        metadata: V1KeyMetadata,
        nonce: ByteArray,
    ): SyncEnvelopeV1 {
        require(nonce.size == profile.nonceBytes) {
            "AES-GCM nonce must be ${profile.nonceBytes} bytes."
        }
        require(metadata.prfInput.size == profile.prfInputBytes) {
            "PRF input must be ${profile.prfInputBytes} bytes."
        }
        require(metadata.kdfSalt.size == profile.kdfSaltBytes) {
            "KDF salt must be ${profile.kdfSaltBytes} bytes."
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(contentKey, "AES"),
            GCMParameterSpec(profile.tagBits, nonce),
        )
        cipher.updateAAD(aad)
        val plaintext = codec.serialize(value)
        val body = when (profile.compression) {
            V1Compression.NONE -> plaintext to null
            V1Compression.GZIP_IF_SMALLER -> {
                val compressed = gzip(plaintext)
                if (compressed.size < plaintext.size) compressed to "gzip" else plaintext to null
            }
        }
        val ciphertext = cipher.doFinal(body.first)
        return SyncEnvelopeV1(
            compression = body.second,
            credentialId = metadata.credentialId,
            rpId = metadata.rpId,
            prfInput = Base64Url.encode(metadata.prfInput),
            kdfSalt = Base64Url.encode(metadata.kdfSalt),
            nonce = Base64Url.encode(nonce),
            ciphertext = Base64Url.encode(ciphertext),
            updatedAt = codec.updatedAt(value),
        )
    }

    fun decrypt(envelope: SyncEnvelopeV1, contentKey: ByteArray): T {
        validateEnvelope(envelope)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(contentKey, "AES"),
                GCMParameterSpec(profile.tagBits, Base64Url.decode(envelope.nonce)),
            )
            cipher.updateAAD(aad)
            val decrypted = cipher.doFinal(Base64Url.decode(envelope.ciphertext))
            val plaintext =
                if (envelope.compression == "gzip") gunzip(decrypted) else decrypted
            codec.parse(plaintext)
        } catch (error: SyncKitError) {
            throw error
        } catch (error: Exception) {
            throw SyncKitError(
                SyncKitErrorCode.CRYPTO,
                "This passkey could not decrypt the ${profile.appId} snapshot.",
                error,
            )
        }
    }

    fun decryptWithSecret(envelope: SyncEnvelopeV1, prfSecret: ByteArray): T {
        val key = deriveContentKey(prfSecret, Base64Url.decode(envelope.kdfSalt))
        return try {
            decrypt(envelope, key)
        } finally {
            key.fill(0)
        }
    }

    fun metadataFromEnvelope(envelope: SyncEnvelopeV1): V1KeyMetadata = envelope.metadata()

    fun parseEnvelope(value: String): SyncEnvelopeV1 =
        try {
            SyncKitJson.instance.decodeFromString(SyncEnvelopeV1.serializer(), value)
                .also(::validateEnvelope)
        } catch (error: SyncKitError) {
            throw error
        } catch (error: Exception) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The file is not a supported ${profile.appId} v1 encrypted snapshot.",
                error,
            )
        }

    fun encodeEnvelope(envelope: SyncEnvelopeV1): String =
        SyncKitJson.instance.encodeToString(SyncEnvelopeV1.serializer(), envelope)

    fun validateEnvelope(envelope: SyncEnvelopeV1) {
        if (
            envelope.schemaVersion != 1 ||
            envelope.algorithm != V1_ALGORITHM ||
            (envelope.compression != null && envelope.compression != "gzip") ||
            (profile.compression == V1Compression.NONE && envelope.compression != null) ||
            envelope.credentialId.isBlank() ||
            envelope.rpId.isBlank() ||
            envelope.prfInput.isBlank() ||
            envelope.kdfSalt.isBlank() ||
            envelope.nonce.isBlank() ||
            envelope.ciphertext.isBlank() ||
            envelope.updatedAt.isBlank()
        ) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The file is not a supported ${profile.appId} v1 encrypted snapshot.",
            )
        }
        validateEncodedLength(envelope.nonce, profile.nonceBytes, "nonce")
        validateEncodedLength(envelope.kdfSalt, profile.kdfSaltBytes, "KDF salt")
        validateEncodedLength(envelope.prfInput, profile.prfInputBytes, "PRF input")
    }

    private fun validateEncodedLength(value: String, expected: Int, label: String) {
        if (Base64Url.decode(value).size != expected) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The v1 envelope $label has an invalid length.",
            )
        }
    }

    private fun gzip(input: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        GZIPOutputStream(output).use { it.write(input) }
        return output.toByteArray()
    }

    private fun gunzip(input: ByteArray): ByteArray =
        try {
            GZIPInputStream(ByteArrayInputStream(input)).use { it.readBytes() }
        } catch (error: Exception) {
            throw SyncKitError(
                SyncKitErrorCode.DECOMPRESSION,
                "The ${profile.appId} snapshot could not be decompressed.",
                error,
            )
        }
}
