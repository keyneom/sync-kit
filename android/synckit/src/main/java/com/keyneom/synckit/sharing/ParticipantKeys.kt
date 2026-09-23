package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.CanonicalJson
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Additional participant keys and recovery codes. See docs/participant-keys.md.
 *
 * Every operation is signed by the participant it concerns, so any participant
 * who can write a dataset may carry it in. Apply them with
 * [SharedBackupController.addParticipantKeys], `removeParticipantKeys`, and
 * `rotateWithAdditionalKey`. Statements are app-scoped, so one signed operation
 * applies to every dataset a participant is in.
 */
object ParticipantKeys {
    /**
     * Signs a request to add [key] to the participant [principalKeyId]. The
     * [authorizer] must be that participant's primary key or one of its existing
     * additional keys; [key] signs too, proving its holder has it.
     */
    fun createAddition(
        appId: String,
        principalKeyId: String,
        authorizer: SharingIdentity,
        key: SharingIdentity,
        purpose: String,
        sealedPrivateKeys: SharedBackupSealedKeyV1? = null,
    ): SharedBackupAdditionalKeyV1 {
        require(appId.isNotBlank()) { "appId must not be empty." }
        require(purpose == "recovery" || purpose == "device") { "purpose must be recovery or device." }
        if (key.publicKey.keyId == principalKeyId) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "A participant's primary key cannot also be one of its additional keys.",
            )
        }
        val statement = additionStatement(
            appId = appId,
            principalKeyId = principalKeyId,
            addedByKeyId = authorizer.publicKey.keyId,
            key = key.publicKey,
            purpose = purpose,
            sealedPrivateKeys = sealedPrivateKeys,
        )
        return SharedBackupAdditionalKeyV1(
            keyId = key.publicKey.keyId,
            encryptionAlgorithm = key.publicKey.encryptionAlgorithm,
            encryptionPublicKey = key.publicKey.encryptionPublicKey,
            signatureAlgorithm = key.publicKey.signatureAlgorithm,
            signingPublicKey = key.publicKey.signingPublicKey,
            principalKeyId = principalKeyId,
            purpose = purpose,
            addedByKeyId = authorizer.publicKey.keyId,
            addition = sign(authorizer, statement),
            possession = sign(key, statement),
            sealedPrivateKeys = sealedPrivateKeys,
        )
    }

    /**
     * Signs a participant's removal of one of its own additional keys. The
     * [authorizer] must be a key of the same participant — its primary key or
     * any of its additional keys, including the one being removed.
     */
    fun createRemoval(
        appId: String,
        authorizer: SharingIdentity,
        key: SharedBackupAdditionalKeyV1,
    ): SharedBackupKeyRemovalV1 {
        require(appId.isNotBlank()) { "appId must not be empty." }
        return SharedBackupKeyRemovalV1(
            keyId = key.keyId,
            removedByKeyId = authorizer.publicKey.keyId,
            removal = sign(authorizer, removalStatement(appId, key.keyId, key.addition)),
        )
    }

    /**
     * Signs "replace my primary key [fromKeyId] with [replacement]", authorized
     * by one of that participant's additional keys — how a lost passkey is
     * replaced. One signed rotation applies to every dataset in the app.
     */
    fun createAuthorizedRotation(
        appId: String,
        fromKeyId: String,
        authorizer: SharingIdentity,
        replacement: SharingIdentity,
    ): SharedBackupAuthorizedKeyRotationV1 {
        require(appId.isNotBlank()) { "appId must not be empty." }
        val statement = rotationStatement(appId, fromKeyId, replacement.publicKey)
        return SharedBackupAuthorizedKeyRotationV1(
            fromKeyId = fromKeyId,
            to = publicKeyFields(replacement.publicKey),
            newKeyProof = sign(replacement, statement),
            authorizedByKeyId = authorizer.publicKey.keyId,
            authorization = sign(authorizer, statement),
        )
    }

    // --- Recovery codes -----------------------------------------------------

    /**
     * Generates a recovery code: 128 random bits as 26 Crockford base32
     * characters plus 2 check characters, in seven groups of four. Show it
     * once; whoever holds it can act as the participant until the key is removed.
     */
    fun generateRecoveryCode(options: SharingCryptoOptions = SharingCryptoOptions()): String {
        val secret = options.randomBytes(SECRET_BYTES)
        try {
            return (encodeSecret(secret) + checkCharacters(secret)).chunked(4).joinToString("-")
        } finally {
            secret.fill(0)
        }
    }

    /** Whether [code] is a well-formed recovery code, for live input validation. */
    fun isRecoveryCodeWellFormed(code: String): Boolean =
        try {
            parseRecoveryCode(code).fill(0)
            true
        } catch (_: SyncKitError) {
            false
        }

    /**
     * Returns the 16-byte secret in a recovery code. Rejects anything that is
     * not a generated code, so a user-chosen passphrase can never be used.
     * Tolerates case, spaces, and hyphens, and reads I and L as 1 and O as 0.
     * The caller zeroes the result.
     */
    fun parseRecoveryCode(code: String): ByteArray {
        val normalized = code.uppercase()
            .replace(Regex("[\\s-]"), "")
            .replace(Regex("[IL]"), "1")
            .replace("O", "0")
        if (
            normalized.length != SECRET_CHARACTERS + CHECK_CHARACTERS ||
            !Regex("^[0-9A-HJKMNP-TV-Z]+$").matches(normalized)
        ) {
            throw SyncKitError(SyncKitErrorCode.KEY, "This is not a recovery code.")
        }
        val secret = decodeSecret(normalized.substring(0, SECRET_CHARACTERS))
        if (checkCharacters(secret) != normalized.substring(SECRET_CHARACTERS)) {
            secret.fill(0)
            throw SyncKitError(
                SyncKitErrorCode.KEY,
                "This recovery code has a typo: it does not match its check characters.",
            )
        }
        return secret
    }

    /**
     * Creates a recovery key for [code]: a fresh sharing identity whose private
     * keys are sealed under the code. Add it with [createAddition] using purpose
     * `recovery` and the returned sealed keys; they travel inside every data file
     * that grants the recovery key, so the code and any one file are enough.
     */
    fun createRecoveryKey(
        appId: String,
        code: String,
        options: SharingCryptoOptions = SharingCryptoOptions(),
    ): RecoveryKey {
        require(appId.isNotBlank()) { "appId must not be empty." }
        val secret = parseRecoveryCode(code)
        val identity = SharingEcKeys.generateIdentity()
        val packed = SharingIdentityMaterial.pack(identity)
        try {
            val kdfSalt = options.randomBytes(32)
            val nonce = options.randomBytes(12)
            val encrypted = SharingEcKeys.encryptAesGcm(
                wrappingKey(secret, kdfSalt),
                nonce,
                CanonicalJson.encodeAad(sealedKeyHeader(appId, identity.publicKey.keyId, kdfSalt, nonce)),
                packed,
            )
            return RecoveryKey(
                identity = identity,
                sealedPrivateKeys = SharedBackupSealedKeyV1(
                    kdf = "HKDF-SHA256",
                    kdfSalt = Base64Url.encode(kdfSalt),
                    nonce = Base64Url.encode(nonce),
                    encryptedPrivateKeys = Base64Url.encode(encrypted),
                ),
            )
        } finally {
            secret.fill(0)
            packed.fill(0)
        }
    }

    /** Unseals one recovery key with its code. */
    fun openRecoveryKey(appId: String, code: String, key: SharedBackupAdditionalKeyV1): SharingIdentity {
        val sealed = key.sealedPrivateKeys
            ?: throw SyncKitError(
                SyncKitErrorCode.KEY,
                "This additional key is not sealed under a recovery code.",
            )
        val secret = parseRecoveryCode(code)
        val packed = try {
            val kdfSalt = Base64Url.decode(sealed.kdfSalt)
            val nonce = Base64Url.decode(sealed.nonce)
            SharingEcKeys.decryptAesGcm(
                wrappingKey(secret, kdfSalt),
                nonce,
                CanonicalJson.encodeAad(sealedKeyHeader(appId, key.keyId, kdfSalt, nonce)),
                Base64Url.decode(sealed.encryptedPrivateKeys),
            )
        } catch (error: Exception) {
            throw SyncKitError(
                SyncKitErrorCode.KEY,
                "This recovery code does not unlock this recovery key.",
                error,
            )
        } finally {
            secret.fill(0)
        }
        try {
            return SharingIdentityMaterial.importIdentity(key.publicKey, packed)
        } finally {
            packed.fill(0)
        }
    }

    /**
     * Finds and unseals the recovery key [code] opens in [envelope]. Needs
     * nothing but the code and this one file, which may be an offline copy.
     */
    fun openRecoveryKeyFromEnvelope(code: String, envelope: SharedBackupEnvelopeV1): OpenedRecoveryKey {
        // Validate once so a typo is reported as a typo, not as "no match".
        parseRecoveryCode(code).fill(0)
        for (key in sharedBackupAdditionalKeys(envelope)) {
            if (key.sealedPrivateKeys == null) continue
            try {
                return OpenedRecoveryKey(openRecoveryKey(envelope.appId, code, key), key)
            } catch (error: SyncKitError) {
                if (error.code != SyncKitErrorCode.KEY) throw error
            }
        }
        throw SyncKitError(
            SyncKitErrorCode.KEY,
            "This recovery code does not unlock any recovery key in this dataset.",
        )
    }

    // --- Signed statements (internal; shared with the envelope verifier) ----

    internal fun publicKeyFields(key: SharingPublicKeyV1): SharingPublicKeyV1 = key.copy()

    private fun publicKeyJson(key: SharingPublicKeyV1): JsonObject = buildJsonObject {
        put("keyId", key.keyId)
        put("encryptionAlgorithm", key.encryptionAlgorithm)
        put("encryptionPublicKey", key.encryptionPublicKey)
        put("signatureAlgorithm", key.signatureAlgorithm)
        put("signingPublicKey", key.signingPublicKey)
    }

    internal fun additionStatement(
        appId: String,
        principalKeyId: String,
        addedByKeyId: String,
        key: SharingPublicKeyV1,
        purpose: String,
        sealedPrivateKeys: SharedBackupSealedKeyV1?,
    ): JsonObject = buildJsonObject {
        put("kind", PARTICIPANT_KEY_ADDITION_KIND)
        put("appId", appId)
        put("principalKeyId", principalKeyId)
        put("addedByKeyId", addedByKeyId)
        put("key", publicKeyJson(key))
        put("purpose", purpose)
        sealedPrivateKeys?.let {
            put(
                "sealedPrivateKeys",
                SyncKitJson.instance.encodeToJsonElement(SharedBackupSealedKeyV1.serializer(), it),
            )
        }
    }

    /** The statement a stored key's signatures cover, as it was first added. */
    internal fun additionStatementForKey(appId: String, key: SharedBackupAdditionalKeyV1): JsonObject =
        additionStatement(
            appId = appId,
            principalKeyId = key.principalKeyId,
            addedByKeyId = key.addedByKeyId,
            key = key.publicKey,
            purpose = key.purpose,
            sealedPrivateKeys = key.sealedPrivateKeys,
        )

    /**
     * Bound to the specific addition it revokes, so it cannot remove a later
     * re-add. It names no principal: the verifier checks the signer belongs to
     * the key's current principal, and a rotation may have moved the key since it
     * was added, so a removal built from the originally added key stays valid.
     */
    internal fun removalStatement(appId: String, keyId: String, addition: String): JsonObject =
        buildJsonObject {
            put("kind", PARTICIPANT_KEY_REMOVAL_KIND)
            put("appId", appId)
            put("keyId", keyId)
            put("addition", addition)
        }

    internal fun rotationStatement(appId: String, fromKeyId: String, to: SharingPublicKeyV1): JsonObject =
        buildJsonObject {
            put("kind", PARTICIPANT_KEY_ROTATION_KIND)
            put("appId", appId)
            put("fromKeyId", fromKeyId)
            put("to", publicKeyJson(to))
        }

    internal fun verifyStatement(signer: SharingPublicKeyV1, statement: JsonObject, signature: String): Boolean =
        try {
            SharingEcKeys.verify(
                SharingEcKeys.signingPublicKey(signer),
                CanonicalJson.encodeAad(statement),
                Base64Url.decode(signature),
            )
        } catch (_: Exception) {
            false
        }

    private fun sign(identity: SharingIdentity, statement: JsonObject): String =
        Base64Url.encode(SharingEcKeys.sign(identity.signingPrivateKey, CanonicalJson.encodeAad(statement)))

    private fun sealedKeyHeader(appId: String, keyId: String, kdfSalt: ByteArray, nonce: ByteArray): JsonObject =
        buildJsonObject {
            put("kind", SEALED_KEY_KIND)
            put("appId", appId)
            put("keyId", keyId)
            put("kdf", "HKDF-SHA256")
            put("kdfSalt", Base64Url.encode(kdfSalt))
            put("nonce", Base64Url.encode(nonce))
        }

    private fun wrappingKey(secret: ByteArray, kdfSalt: ByteArray): ByteArray =
        SharingEcKeys.hkdf(secret, kdfSalt, RECOVERY_KDF_INFO.toByteArray(Charsets.UTF_8), 32)

    /** 128 bits → 26 characters; the final 2 bits are zero padding. */
    private fun encodeSecret(secret: ByteArray): String {
        val output = StringBuilder()
        var buffer = 0
        var bits = 0
        for (byte in secret) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                output.append(CROCKFORD[(buffer ushr (bits - 5)) and 31])
                bits -= 5
            }
            buffer = buffer and ((1 shl bits) - 1)
        }
        if (bits > 0) output.append(CROCKFORD[(buffer shl (5 - bits)) and 31])
        return output.toString()
    }

    private fun decodeSecret(characters: String): ByteArray {
        val secret = ByteArray(SECRET_BYTES)
        var buffer = 0
        var bits = 0
        var index = 0
        for (character in characters) {
            buffer = (buffer shl 5) or CROCKFORD.indexOf(character)
            bits += 5
            if (bits >= 8) {
                if (index >= SECRET_BYTES) break
                secret[index++] = ((buffer ushr (bits - 8)) and 0xff).toByte()
                bits -= 8
            }
            buffer = buffer and ((1 shl bits) - 1)
        }
        if (index != SECRET_BYTES || buffer != 0) {
            secret.fill(0)
            throw SyncKitError(SyncKitErrorCode.KEY, "This is not a recovery code.")
        }
        return secret
    }

    /** Two characters (10 bits) of SHA-256 over the secret, to catch typos. */
    private fun checkCharacters(secret: ByteArray): String {
        val digest = SharingEcKeys.digestSha256(secret)
        val check = (((digest[0].toInt() and 0xff) shl 8) or (digest[1].toInt() and 0xff)) ushr 6
        return "${CROCKFORD[(check ushr 5) and 31]}${CROCKFORD[check and 31]}"
    }

    private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    private const val SECRET_BYTES = 16
    private const val SECRET_CHARACTERS = 26
    private const val CHECK_CHARACTERS = 2
    private const val RECOVERY_KDF_INFO = "sync-kit participant recovery key v1"
    private const val SEALED_KEY_KIND = "sync-kit-sealed-participant-key"
}

/** A recovery key's identity and its private keys sealed under the recovery code. */
data class RecoveryKey(
    val identity: SharingIdentity,
    val sealedPrivateKeys: SharedBackupSealedKeyV1,
)

/** A recovery key opened from a dataset, and the additional key it was found as. */
data class OpenedRecoveryKey(
    val identity: SharingIdentity,
    val key: SharedBackupAdditionalKeyV1,
)
