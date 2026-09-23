package com.keyneom.synckit.crypto

import com.keyneom.synckit.core.CreatedKey
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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

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

    /**
     * Encrypts [value]. An existing v2 snapshot (its locks in [metadata]) stays
     * v2 with the same locks; otherwise a new snapshot takes the profile's
     * `writeVersion`. An existing v1 snapshot is never upgraded here — only by
     * an explicit [setRecoveryCode] or [migrate].
     */
    fun encrypt(value: T, contentKey: ByteArray, metadata: V1KeyMetadata): SyncEnvelopeV1 {
        metadata.locks?.let { locks ->
            val material = openPasskeyLock(locks, metadata, contentKey)
            try {
                return sealV2(value, material, locks, metadata)
            } finally {
                material.fill(0)
            }
        }
        if (profile.writeVersion == 2) return encryptNewV2(value, contentKey, metadata)
        return encryptWithNonce(value, contentKey, metadata, randomBytes(profile.nonceBytes))
    }

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
        if (envelope.schemaVersion == 2) {
            val material = openPasskeyLock(requireLocks(envelope), envelope.metadata(), contentKey)
            try {
                return unsealV2(envelope, material)
            } finally {
                material.fill(0)
            }
        }
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
        if (envelope.schemaVersion == 2) {
            validateV2(envelope)
            return
        }
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

    // --- Snapshot v2 and recovery codes. See docs/snapshot-recovery.md. ------

    /** Adds, replaces, or (with null) removes the recovery lock. Upgrades a v1 snapshot to v2. */
    fun setRecoveryCode(envelope: SyncEnvelopeV1, contentKey: ByteArray, recoveryCode: String?): SyncEnvelopeV1 {
        requireV2Reads()
        val value = decrypt(envelope, contentKey)
        val passkey = envelope.metadata()
        val (material, locks) = if (envelope.schemaVersion == 2) {
            openPasskeyLock(requireLocks(envelope), passkey, contentKey) to requireLocks(envelope)
        } else {
            val material = randomBytes(MATERIAL_BYTES)
            val contentSalt = Base64Url.encode(randomBytes(32))
            material to SnapshotLocksV2(
                appId = profile.appId,
                contentSalt = contentSalt,
                passkeyKey = passkeyLock(profile.appId, contentKey, passkey, contentSalt, material),
            )
        }
        try {
            val next = locks.copy(
                recoveryKey = recoveryCode?.let { recoveryLock(locks.appId, it, locks.contentSalt, material) },
            )
            return sealV2(value, material, next, passkey)
        } finally {
            material.fill(0)
        }
    }

    fun decryptWithRecoveryCode(envelope: SyncEnvelopeV1, recoveryCode: String): T {
        requireV2Reads()
        val material = openRecoveryLock(requireV2(envelope), recoveryCode)
        try {
            return unsealV2(envelope, material)
        } finally {
            material.fill(0)
        }
    }

    /** Opens with the recovery code and locks [value] under a new passkey, keeping the recovery lock. */
    fun relockWithRecoveryCode(
        envelope: SyncEnvelopeV1,
        recoveryCode: String,
        replacement: CreatedKey,
        value: T,
    ): SyncEnvelopeV1 {
        requireV2Reads()
        val locks = requireLocks(requireV2(envelope))
        val material = openRecoveryLock(envelope, recoveryCode)
        try {
            val next = locks.copy(
                passkeyKey = passkeyLock(locks.appId, replacement.key, replacement.metadata, locks.contentSalt, material),
            )
            return sealV2(value, material, next, replacement.metadata)
        } finally {
            material.fill(0)
        }
    }

    /** Explicit, reversible version change. Moving to 1 removes any recovery lock. */
    fun migrate(envelope: SyncEnvelopeV1, contentKey: ByteArray, version: Int): SyncEnvelopeV1 {
        require(version == 1 || version == 2) { "version must be 1 or 2." }
        validateEnvelope(envelope)
        if (envelope.schemaVersion == version) return envelope
        val value = decrypt(envelope, contentKey)
        val passkey = V1KeyMetadata(envelope.credentialId, envelope.rpId, Base64Url.decode(envelope.prfInput), Base64Url.decode(envelope.kdfSalt))
        // The passkey-derived key is exactly the v1 content key.
        if (version == 1) return encryptWithNonce(value, contentKey, passkey, randomBytes(profile.nonceBytes))
        requireV2Reads()
        return encryptNewV2(value, contentKey, passkey)
    }

    private fun encryptNewV2(value: T, contentKey: ByteArray, metadata: V1KeyMetadata): SyncEnvelopeV1 {
        val material = randomBytes(MATERIAL_BYTES)
        try {
            val contentSalt = Base64Url.encode(randomBytes(32))
            val locks = SnapshotLocksV2(
                appId = profile.appId,
                contentSalt = contentSalt,
                passkeyKey = passkeyLock(profile.appId, contentKey, metadata, contentSalt, material),
            )
            return sealV2(value, material, locks, metadata)
        } finally {
            material.fill(0)
        }
    }

    private fun sealV2(value: T, material: ByteArray, locks: SnapshotLocksV2, passkey: V1KeyMetadata): SyncEnvelopeV1 {
        val plaintext = codec.serialize(value)
        val (body, compression) = when (profile.compression) {
            V1Compression.NONE -> plaintext to null
            V1Compression.GZIP_IF_SMALLER -> {
                val compressed = gzip(plaintext)
                if (compressed.size < plaintext.size) compressed to "gzip" else plaintext to null
            }
        }
        val draft = SyncEnvelopeV1(
            schemaVersion = 2,
            compression = compression,
            credentialId = passkey.credentialId,
            rpId = passkey.rpId,
            prfInput = Base64Url.encode(passkey.prfInput),
            kdfSalt = Base64Url.encode(passkey.kdfSalt),
            nonce = "",
            ciphertext = "",
            updatedAt = codec.updatedAt(value),
            appId = locks.appId,
            contentSalt = locks.contentSalt,
            passkeyKey = locks.passkeyKey,
            recoveryKey = locks.recoveryKey,
        )
        val nonce = randomBytes(profile.nonceBytes)
        val key = hkdf(material, Base64Url.decode(locks.contentSalt), CONTENT_KEY_INFO)
        try {
            val ciphertext = aesGcm(Cipher.ENCRYPT_MODE, key, nonce, payloadAad(draft), body)
            return draft.copy(nonce = Base64Url.encode(nonce), ciphertext = Base64Url.encode(ciphertext))
        } finally {
            key.fill(0)
        }
    }

    private fun unsealV2(envelope: SyncEnvelopeV1, material: ByteArray): T {
        val key = hkdf(material, Base64Url.decode(requireNotNull(envelope.contentSalt)), CONTENT_KEY_INFO)
        return try {
            val decrypted = aesGcm(
                Cipher.DECRYPT_MODE,
                key,
                Base64Url.decode(envelope.nonce),
                payloadAad(envelope),
                Base64Url.decode(envelope.ciphertext),
            )
            codec.parse(if (envelope.compression == "gzip") gunzip(decrypted) else decrypted)
        } catch (error: SyncKitError) {
            throw error
        } catch (error: Exception) {
            throw SyncKitError(
                SyncKitErrorCode.CRYPTO,
                "The ${profile.appId} snapshot could not be decrypted.",
                error,
            )
        } finally {
            key.fill(0)
        }
    }

    private fun passkeyLock(
        appId: String,
        contentKey: ByteArray,
        passkey: V1KeyMetadata,
        contentSalt: String,
        material: ByteArray,
    ): SnapshotWrappedKeyV2 {
        val nonce = randomBytes(12)
        return SnapshotWrappedKeyV2(
            nonce = Base64Url.encode(nonce),
            wrappedKey = Base64Url.encode(
                aesGcm(Cipher.ENCRYPT_MODE, contentKey, nonce, passkeyLockAad(appId, passkey, contentSalt), material),
            ),
        )
    }

    private fun openPasskeyLock(locks: SnapshotLocksV2, passkey: V1KeyMetadata, contentKey: ByteArray): ByteArray =
        try {
            aesGcm(
                Cipher.DECRYPT_MODE,
                contentKey,
                Base64Url.decode(locks.passkeyKey.nonce),
                passkeyLockAad(locks.appId, passkey, locks.contentSalt),
                Base64Url.decode(locks.passkeyKey.wrappedKey),
            )
        } catch (error: Exception) {
            throw SyncKitError(
                SyncKitErrorCode.CRYPTO,
                "This passkey could not open the ${locks.appId} snapshot.",
                error,
            )
        }

    private fun recoveryLock(appId: String, recoveryCode: String, contentSalt: String, material: ByteArray): SnapshotRecoveryKeyV2 {
        val secret = RecoveryCodes.parse(recoveryCode)
        try {
            val kdfSalt = randomBytes(32)
            val recoveryKey = hkdf(secret, kdfSalt, RECOVERY_KEY_INFO)
            try {
                val nonce = randomBytes(12)
                val encodedSalt = Base64Url.encode(kdfSalt)
                return SnapshotRecoveryKeyV2(
                    kdfSalt = encodedSalt,
                    nonce = Base64Url.encode(nonce),
                    wrappedKey = Base64Url.encode(
                        aesGcm(Cipher.ENCRYPT_MODE, recoveryKey, nonce, recoveryLockAad(appId, encodedSalt, contentSalt), material),
                    ),
                )
            } finally {
                recoveryKey.fill(0)
            }
        } finally {
            secret.fill(0)
        }
    }

    private fun openRecoveryLock(envelope: SyncEnvelopeV1, recoveryCode: String): ByteArray {
        val lock = envelope.recoveryKey
            ?: throw SyncKitError(SyncKitErrorCode.KEY, "This snapshot has no recovery code.")
        val appId = requireNotNull(envelope.appId)
        val contentSalt = requireNotNull(envelope.contentSalt)
        val secret = RecoveryCodes.parse(recoveryCode)
        val recoveryKey = hkdf(secret, Base64Url.decode(lock.kdfSalt), RECOVERY_KEY_INFO)
        return try {
            aesGcm(
                Cipher.DECRYPT_MODE,
                recoveryKey,
                Base64Url.decode(lock.nonce),
                recoveryLockAad(appId, lock.kdfSalt, contentSalt),
                Base64Url.decode(lock.wrappedKey),
            )
        } catch (error: Exception) {
            throw SyncKitError(SyncKitErrorCode.KEY, "This recovery code does not unlock this snapshot.", error)
        } finally {
            secret.fill(0)
            recoveryKey.fill(0)
        }
    }

    /**
     * The authenticated header, built from the known fields only, exactly as
     * the web package builds it: every field but the nonce and ciphertext.
     */
    private fun payloadAad(envelope: SyncEnvelopeV1): ByteArray {
        val passkeyKey = requireNotNull(envelope.passkeyKey)
        val header = buildJsonObject {
            put("schemaVersion", 2)
            put("appId", requireNotNull(envelope.appId))
            put("algorithm", envelope.algorithm)
            envelope.compression?.let { put("compression", it) }
            put("credentialId", envelope.credentialId)
            put("rpId", envelope.rpId)
            put("prfInput", envelope.prfInput)
            put("kdfSalt", envelope.kdfSalt)
            put("contentSalt", requireNotNull(envelope.contentSalt))
            put(
                "passkeyKey",
                buildJsonObject {
                    put("nonce", passkeyKey.nonce)
                    put("wrappedKey", passkeyKey.wrappedKey)
                },
            )
            envelope.recoveryKey?.let { lock ->
                put(
                    "recoveryKey",
                    buildJsonObject {
                        put("kdfSalt", lock.kdfSalt)
                        put("nonce", lock.nonce)
                        put("wrappedKey", lock.wrappedKey)
                    },
                )
            }
            put("updatedAt", envelope.updatedAt)
        }
        return CanonicalJson.encodeAad(
            buildJsonObject {
                put("aad", profile.aad)
                put("header", header)
            },
        )
    }

    private fun passkeyLockAad(appId: String, passkey: V1KeyMetadata, contentSalt: String): ByteArray =
        CanonicalJson.encodeAad(
            buildJsonObject {
                put("kind", "sync-kit-snapshot-passkey-lock")
                put("appId", appId)
                put("credentialId", passkey.credentialId)
                put("rpId", passkey.rpId)
                put("prfInput", Base64Url.encode(passkey.prfInput))
                put("kdfSalt", Base64Url.encode(passkey.kdfSalt))
                put("contentSalt", contentSalt)
            },
        )

    private fun recoveryLockAad(appId: String, kdfSalt: String, contentSalt: String): ByteArray =
        CanonicalJson.encodeAad(
            buildJsonObject {
                put("kind", "sync-kit-snapshot-recovery-lock")
                put("appId", appId)
                put("kdfSalt", kdfSalt)
                put("contentSalt", contentSalt)
            },
        )

    /** RFC 5869 HKDF-SHA256, one 32-byte block — as WebCrypto derives an AES-256 key. */
    private fun hkdf(inputKeyMaterial: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(salt, "HmacSHA256"))
        val pseudoRandomKey = extract.doFinal(inputKeyMaterial)
        val expand = Mac.getInstance("HmacSHA256")
        expand.init(SecretKeySpec(pseudoRandomKey, "HmacSHA256"))
        expand.update(info)
        expand.update(1)
        val output = expand.doFinal().copyOf(32)
        pseudoRandomKey.fill(0)
        return output
    }

    private fun aesGcm(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, input: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(profile.tagBits, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(input)
    }

    private fun requireV2Reads() {
        if (2 !in profile.readVersions) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "Snapshot recovery and v2 need 2 in the ${profile.appId} profile's readVersions.",
            )
        }
    }

    private fun requireV2(envelope: SyncEnvelopeV1): SyncEnvelopeV1 {
        validateEnvelope(envelope)
        if (envelope.schemaVersion != 2) {
            throw SyncKitError(SyncKitErrorCode.KEY, "This ${profile.appId} snapshot has no recovery code.")
        }
        return envelope
    }

    private fun requireLocks(envelope: SyncEnvelopeV1): SnapshotLocksV2 =
        envelope.locks() ?: throw SyncKitError(
            SyncKitErrorCode.COMPATIBILITY,
            "The file is not a supported ${profile.appId} v2 encrypted snapshot.",
        )

    private fun validateV2(envelope: SyncEnvelopeV1) {
        if (2 !in profile.readVersions) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "This ${profile.appId} snapshot is version 2; add 2 to the profile's readVersions to read it.",
            )
        }
        val recoveryKey = envelope.recoveryKey
        if (
            envelope.algorithm != V1_ALGORITHM ||
            envelope.appId.isNullOrBlank() ||
            envelope.contentSalt.isNullOrBlank() ||
            envelope.passkeyKey == null ||
            envelope.passkeyKey.nonce.isBlank() ||
            envelope.passkeyKey.wrappedKey.isBlank() ||
            (recoveryKey != null && (recoveryKey.kdfSalt.isBlank() || recoveryKey.nonce.isBlank() || recoveryKey.wrappedKey.isBlank())) ||
            (envelope.compression != null && envelope.compression != "gzip") ||
            (profile.compression == V1Compression.NONE && envelope.compression != null) ||
            envelope.credentialId.isBlank() || envelope.rpId.isBlank() ||
            envelope.prfInput.isBlank() || envelope.kdfSalt.isBlank() ||
            envelope.nonce.isBlank() || envelope.ciphertext.isBlank() || envelope.updatedAt.isBlank()
        ) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The file is not a supported ${profile.appId} v2 encrypted snapshot.",
            )
        }
        if (envelope.appId != profile.appId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "This snapshot belongs to ${envelope.appId}, not ${profile.appId}.",
            )
        }
        validateEncodedLength(envelope.nonce, profile.nonceBytes, "nonce", 2)
        validateEncodedLength(envelope.kdfSalt, profile.kdfSaltBytes, "KDF salt", 2)
        validateEncodedLength(envelope.prfInput, profile.prfInputBytes, "PRF input", 2)
        validateEncodedLength(envelope.contentSalt, 32, "content salt", 2)
        validateEncodedLength(envelope.passkeyKey.nonce, 12, "passkey-lock nonce", 2)
        recoveryKey?.let {
            validateEncodedLength(it.nonce, 12, "recovery-lock nonce", 2)
            validateEncodedLength(it.kdfSalt, 32, "recovery-lock salt", 2)
        }
    }

    private fun validateEncodedLength(value: String, expected: Int, label: String, version: Int = 1) {
        if (Base64Url.decode(value).size != expected) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The v$version envelope $label has an invalid length.",
            )
        }
    }

    private fun gzip(input: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        GZIPOutputStream(output).use { it.write(input) }
        return output.toByteArray()
    }

    private companion object {
        const val MATERIAL_BYTES = 32
        val CONTENT_KEY_INFO = "sync-kit snapshot content key v2".toByteArray(Charsets.UTF_8)
        val RECOVERY_KEY_INFO = "sync-kit snapshot recovery key v2".toByteArray(Charsets.UTF_8)
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
