package com.keyneom.synckit.sharing

import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.CanonicalJson
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

internal object SharingEcKeys {
    private val keyFactory: KeyFactory by lazy { KeyFactory.getInstance("EC") }
    private val p256: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
    }

    fun generateIdentity(): SharingIdentity {
        val encryption = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val signing = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val encryptionPublicKey = exportUncompressedPublicKey(encryption.public)
        val signingPublicKey = exportUncompressedPublicKey(signing.public)
        val publicKey = createSharingPublicKeyV1(encryptionPublicKey, signingPublicKey)
        return SharingIdentity(
            publicKey = publicKey,
            encryptionPrivateKey = encryption.private as ECPrivateKey,
            signingPrivateKey = signing.private as ECPrivateKey,
        )
    }

    fun identityFromPrivateKeyD(
        encryptionD: ByteArray,
        signingD: ByteArray,
        publicKey: SharingPublicKeyV1,
    ): SharingIdentity {
        val encryptionPrivate = privateKeyFromD(encryptionD)
        val signingPrivate = privateKeyFromD(signingD)
        return SharingIdentity(
            publicKey = publicKey,
            encryptionPrivateKey = encryptionPrivate,
            signingPrivateKey = signingPrivate,
        )
    }

    fun createSharingPublicKeyV1(
        encryptionPublicKey: String,
        signingPublicKey: String,
    ): SharingPublicKeyV1 {
        val digest = MessageDigest.getInstance("SHA-256").digest(
            CanonicalJson.encodeAad(
                buildJsonObject {
                    put("encryptionAlgorithm", SHARING_ENCRYPTION_ALGORITHM)
                    put("encryptionPublicKey", encryptionPublicKey)
                    put("signatureAlgorithm", SHARING_SIGNATURE_ALGORITHM)
                    put("signingPublicKey", signingPublicKey)
                },
            ),
        )
        return SharingPublicKeyV1(
            keyId = Base64Url.encode(digest),
            encryptionAlgorithm = SHARING_ENCRYPTION_ALGORITHM,
            encryptionPublicKey = encryptionPublicKey,
            signatureAlgorithm = SHARING_SIGNATURE_ALGORITHM,
            signingPublicKey = signingPublicKey,
        )
    }

    fun exportUncompressedPublicKey(publicKey: PublicKey): String {
        val ecPublic = publicKey as ECPublicKey
        val x = ecPublic.w.affineX.toByteArray().padTo(32)
        val y = ecPublic.w.affineY.toByteArray().padTo(32)
        return Base64Url.encode(byteArrayOf(4) + x + y)
    }

    fun publicKeyFromUncompressed(raw: ByteArray): PublicKey {
        require(raw.size == 65 && raw[0] == 4.toByte()) {
            "Expected uncompressed P-256 key."
        }
        val x = BigInteger(1, raw.copyOfRange(1, 33))
        val y = BigInteger(1, raw.copyOfRange(33, 65))
        return keyFactory.generatePublic(ECPublicKeySpec(ECPoint(x, y), p256))
    }

    fun privateKeyFromD(d: ByteArray): ECPrivateKey =
        keyFactory.generatePrivate(
            ECPrivateKeySpec(BigInteger(1, d), p256),
        ) as ECPrivateKey

    fun ecdh(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey)
        agreement.doPhase(publicKey, true)
        return agreement.generateSecret()
    }

    fun sign(privateKey: ECPrivateKey, message: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSAinP1363Format")
        signature.initSign(privateKey)
        signature.update(message)
        return signature.sign()
    }

    fun verify(publicKey: PublicKey, message: ByteArray, proof: ByteArray): Boolean {
        val signature = Signature.getInstance("SHA256withECDSAinP1363Format")
        signature.initVerify(publicKey)
        signature.update(message)
        return signature.verify(proof)
    }

    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        val output = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(previous)
            mac.update(info)
            mac.update(counter++.toByte())
            previous = mac.doFinal()
            val copied = minOf(previous.size, length - offset)
            System.arraycopy(previous, 0, output, offset, copied)
            offset += copied
        }
        prk.fill(0)
        return output
    }

    fun decryptAesGcm(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, nonce),
        )
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    fun encryptAesGcm(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, nonce),
        )
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    fun digestSha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    fun signingPublicKey(participant: SharingPublicKeyV1): PublicKey =
        publicKeyFromUncompressed(Base64Url.decode(participant.signingPublicKey))

    fun signingPublicKey(participant: SharedBackupParticipantV1): PublicKey =
        signingPublicKey(
            SharingPublicKeyV1(
                keyId = participant.keyId,
                encryptionAlgorithm = participant.encryptionAlgorithm,
                encryptionPublicKey = participant.encryptionPublicKey,
                signatureAlgorithm = participant.signatureAlgorithm,
                signingPublicKey = participant.signingPublicKey,
            ),
        )

    fun signingPublicKey(response: SharingPublicKeyResponseV1): PublicKey =
        signingPublicKey(
            SharingPublicKeyV1(
                keyId = response.keyId,
                encryptionAlgorithm = response.encryptionAlgorithm,
                encryptionPublicKey = response.encryptionPublicKey,
                signatureAlgorithm = response.signatureAlgorithm,
                signingPublicKey = response.signingPublicKey,
            ),
        )

    fun encryptionPublicKey(participant: SharingPublicKeyV1): PublicKey =
        publicKeyFromUncompressed(Base64Url.decode(participant.encryptionPublicKey))

    fun encryptionPublicKey(participant: SharedBackupParticipantV1): PublicKey =
        encryptionPublicKey(
            SharingPublicKeyV1(
                keyId = participant.keyId,
                encryptionAlgorithm = participant.encryptionAlgorithm,
                encryptionPublicKey = participant.encryptionPublicKey,
                signatureAlgorithm = participant.signatureAlgorithm,
                signingPublicKey = participant.signingPublicKey,
            ),
        )

    private fun ByteArray.padTo(length: Int): ByteArray {
        if (size == length) return this
        if (size > length) return copyOfRange(size - length, size)
        return ByteArray(length - size) + this
    }
}

data class SharingIdentity(
    val publicKey: SharingPublicKeyV1,
    val encryptionPrivateKey: ECPrivateKey,
    val signingPrivateKey: ECPrivateKey,
)

data class SharedBackupParticipantInput(
    val publicKey: SharingPublicKeyV1,
    val role: SharingRole,
    val accepted: SharingAcceptanceProvenanceV1? = null,
)

data class AcceptedSharingGrantV1(
    val datasetId: String,
    val participant: SharedBackupParticipantInput,
)

data class SharingCryptoOptions(
    val now: () -> java.util.Date = { java.util.Date() },
    val randomUuid: () -> String = { java.util.UUID.randomUUID().toString() },
    val randomBytes: (Int) -> ByteArray = { length ->
        ByteArray(length).also { java.security.SecureRandom().nextBytes(it) }
    },
)

object SharingCrypto {
    fun generateIdentity(): SharingIdentity = SharingEcKeys.generateIdentity()

    fun parseSharedBackupEnvelopeV1(json: String): SharedBackupEnvelopeV1 =
        SharingParsing.parseSharedBackupEnvelopeV1(
            SyncKitJson.instance.decodeFromString(
                SharedBackupEnvelopeV1.serializer(),
                json,
            ),
        )

    fun parseSharedBackupEnvelopeV1(envelope: SharedBackupEnvelopeV1): SharedBackupEnvelopeV1 =
        SharingParsing.parseSharedBackupEnvelopeV1(envelope)

    fun parseSharingInvitationV1(json: String): SharingInvitationV1 =
        parseSharingInvitationV1(
            SyncKitJson.instance.decodeFromString(
                SharingInvitationV1.serializer(),
                json,
            ),
        )

    fun parseSharingInvitationV1(value: SharingInvitationV1): SharingInvitationV1 =
        SharingParsing.parseSharingInvitationV1(value)

    fun parseSharingPublicKeyResponseV1(json: String): SharingPublicKeyResponseV1 =
        parseSharingPublicKeyResponseV1(
            SyncKitJson.instance.decodeFromString(
                SharingPublicKeyResponseV1.serializer(),
                json,
            ),
        )

    fun parseSharingPublicKeyResponseV1(value: SharingPublicKeyResponseV1): SharingPublicKeyResponseV1 =
        SharingParsing.parseSharingPublicKeyResponseV1(value)

    fun verifySharedBackupEnvelopeV1(
        envelope: SharedBackupEnvelopeV1,
        options: VerifySharedBackupOptions = VerifySharedBackupOptions(),
    ): SharedBackupEnvelopeV1 {
        val parsed = parseSharedBackupEnvelopeV1(envelope)
        val participants = verifyAccessControl(
            parsed.accessControl,
            options.trustedOwnerKeyId,
            parsed.appId,
            parsed.backupId,
        )
        val author = sharedBackupParticipant(parsed, parsed.authorKeyId)
            ?: throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "The shared-backup author is not an authorized writer.",
            )
        if (!canWriteSharedBackup(author.role)) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "The shared-backup author is not an authorized writer.",
            )
        }
        assertParticipantKeys(participants)
        val unsigned = envelopeJsonWithoutSignature(parsed)
        if (!SharingEcKeys.verify(
                SharingEcKeys.signingPublicKey(author),
                CanonicalJson.encodeAad(unsigned),
                Base64Url.decode(parsed.signature),
            )
        ) {
            throw SyncKitError(
                SyncKitErrorCode.CRYPTO,
                "The shared-backup signature is invalid.",
            )
        }
        return parsed
    }

    fun <T> decryptSharedBackupEnvelopeV1(
        envelope: SharedBackupEnvelopeV1,
        codec: SharedBackupCodec<T>,
        identity: SharingIdentity,
        options: VerifySharedBackupOptions = VerifySharedBackupOptions(),
    ): T {
        assertIdentity(identity)
        val verified = verifySharedBackupEnvelopeV1(envelope, options)
        val participant = sharedBackupParticipant(verified, identity.publicKey.keyId)
            ?: throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "This identity is not a participant in the shared backup.",
            )
        val grant = verified.keyGrants.find { it.recipientKeyId == identity.publicKey.keyId }
            ?: throw SyncKitError(
                SyncKitErrorCode.KEY,
                "No content-key grant exists for this identity.",
            )
        val header = sharedBackupHeaderJson(verified)
        val rawContentKey = try {
            unwrapContentKey(grant, header, identity.encryptionPrivateKey)
        } catch (error: Exception) {
            throw SyncKitError(
                SyncKitErrorCode.KEY,
                "This identity could not unwrap the shared-backup content key.",
                error,
            )
        }
        try {
            val plaintext = SharingEcKeys.decryptAesGcm(
                rawContentKey,
                Base64Url.decode(verified.payloadNonce),
                CanonicalJson.encodeAad(header),
                Base64Url.decode(verified.ciphertext),
            )
            return try {
                codec.parse(SyncKitJson.instance.parseToJsonElement(plaintext.toString(Charsets.UTF_8)))
            } catch (error: Exception) {
                throw SyncKitError(
                    SyncKitErrorCode.COMPATIBILITY,
                    "The decrypted shared-backup payload is invalid.",
                    error,
                )
            }
        } catch (error: SyncKitError) {
            throw error
        } catch (error: Exception) {
            throw SyncKitError(
                SyncKitErrorCode.CRYPTO,
                "This identity could not decrypt the shared backup.",
                error,
            )
        } finally {
            rawContentKey.fill(0)
        }
    }

    fun verifySharingInvitationV1(
        invitation: SharingInvitationV1,
        options: SharingCryptoOptions = SharingCryptoOptions(),
    ): SharingInvitationV1 {
        val parsed = parseSharingInvitationV1(invitation)
        val expectedOwner = SharingEcKeys.createSharingPublicKeyV1(
            parsed.owner.encryptionPublicKey,
            parsed.owner.signingPublicKey,
        )
        if (expectedOwner.keyId != parsed.owner.keyId) {
            throw SyncKitError(
                SyncKitErrorCode.KEY,
                "The invitation owner fingerprint does not match its keys.",
            )
        }
        val unsigned = invitationJsonWithoutSignature(parsed)
        if (!SharingEcKeys.verify(
                SharingEcKeys.signingPublicKey(parsed.owner),
                CanonicalJson.encodeAad(unsigned),
                Base64Url.decode(parsed.signature),
            )
        ) {
            throw SyncKitError(
                SyncKitErrorCode.CRYPTO,
                "The sharing invitation signature is invalid.",
            )
        }
        parsed.expiresAt?.let { expiresAt ->
            if (java.time.Instant.parse(expiresAt).toEpochMilli() <= options.now().time) {
                throw SyncKitError(
                    SyncKitErrorCode.AUTHORIZATION,
                    "The sharing invitation has expired.",
                )
            }
        }
        return parsed
    }

    fun verifySharingPublicKeyResponseV1(response: SharingPublicKeyResponseV1): SharingPublicKeyResponseV1 {
        val parsed = parseSharingPublicKeyResponseV1(response)
        val expectedKey = SharingEcKeys.createSharingPublicKeyV1(
            parsed.encryptionPublicKey,
            parsed.signingPublicKey,
        )
        if (expectedKey.keyId != parsed.keyId) {
            throw SyncKitError(
                SyncKitErrorCode.KEY,
                "The public-key response fingerprint does not match its keys.",
            )
        }
        val unsigned = responseJsonWithoutProof(parsed)
        if (!SharingEcKeys.verify(
                SharingEcKeys.signingPublicKey(parsed),
                CanonicalJson.encodeAad(unsigned),
                Base64Url.decode(parsed.proof),
            )
        ) {
            throw SyncKitError(
                SyncKitErrorCode.KEY,
                "The public-key response does not prove possession of its signing key.",
            )
        }
        return parsed
    }

    fun createSharingPublicKeyResponseV1(
        identity: SharingIdentity,
        appId: String,
        exchangeId: String,
        options: SharingCryptoOptions = SharingCryptoOptions(),
        accountBinding: SharingAccountBindingV1? = null,
    ): SharingPublicKeyResponseV1 {
        requireNonEmpty(appId, "appId")
        requireNonEmpty(exchangeId, "exchangeId")
        assertIdentity(identity)
        val unsigned = buildJsonObject {
            put("schemaVersion", 1)
            put("kind", SHARING_KEY_KIND)
            put("appId", appId)
            put("exchangeId", exchangeId)
            put("createdAt", options.now().toInstant().toString())
            put("keyId", identity.publicKey.keyId)
            put("encryptionAlgorithm", identity.publicKey.encryptionAlgorithm)
            put("encryptionPublicKey", identity.publicKey.encryptionPublicKey)
            put("signatureAlgorithm", identity.publicKey.signatureAlgorithm)
            put("signingPublicKey", identity.publicKey.signingPublicKey)
            accountBinding?.let { binding ->
                put("accountBinding", SyncKitJson.instance.encodeToJsonElement(
                    SharingAccountBindingV1.serializer(),
                    binding,
                ))
            }
        }
        val proof = SharingEcKeys.sign(
            identity.signingPrivateKey,
            CanonicalJson.encodeAad(unsigned),
        )
        return parseSharingPublicKeyResponseV1(
            SyncKitJson.instance.decodeFromJsonElement(
                SharingPublicKeyResponseV1.serializer(),
                buildJsonObject {
                    unsigned.forEach { (key, value) -> put(key, value) }
                    put("proof", Base64Url.encode(proof))
                },
            ),
        )
    }

    fun createSharingInvitationV1(
        identity: SharingIdentity,
        input: CreateSharingInvitationInput,
        options: SharingCryptoOptions = SharingCryptoOptions(),
    ): SharingInvitationV1 {
        requireNonEmpty(input.appId, "appId")
        requireNonEmpty(input.appFolderId, "appFolderId")
        requireNonEmpty(input.recipientDrivePermissionId, "recipientDrivePermissionId")
        val requestedGrants = normalizedRequestedGrants(input.requestedGrants)
        assertIdentity(identity)
        val unsigned = buildJsonObject {
            put("schemaVersion", 1)
            put("kind", SHARING_INVITATION_KIND)
            put("appId", input.appId)
            put("appFolderId", input.appFolderId)
            put("exchangeId", input.exchangeId ?: options.randomUuid())
            put("recipientDrivePermissionId", input.recipientDrivePermissionId)
            put(
                "requestedGrants",
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharingDatasetGrantV1.serializer()),
                    requestedGrants,
                ),
            )
            put("trustedOwnerKeyId", input.trustedOwnerKeyId ?: identity.publicKey.keyId)
            put("createdAt", options.now().toInstant().toString())
            input.expiresAt?.let { put("expiresAt", it) }
            put(
                "owner",
                SyncKitJson.instance.encodeToJsonElement(
                    SharingPublicKeyV1.serializer(),
                    identity.publicKey,
                ),
            )
        }
        val signature = SharingEcKeys.sign(
            identity.signingPrivateKey,
            CanonicalJson.encodeAad(unsigned),
        )
        return parseSharingInvitationV1(
            SyncKitJson.instance.decodeFromJsonElement(
                SharingInvitationV1.serializer(),
                buildJsonObject {
                    unsigned.forEach { (key, value) -> put(key, value) }
                    put("signature", Base64Url.encode(signature))
                },
            ),
        )
    }

    fun acceptSharingPublicKeyResponseV1(
        invitation: SharingInvitationV1,
        response: SharingPublicKeyResponseV1,
        acceptedByKeyId: String,
        drivePermissionId: String,
        options: SharingCryptoOptions = SharingCryptoOptions(),
        googleSubject: String? = null,
    ): List<AcceptedSharingGrantV1> {
        requireNonEmpty(acceptedByKeyId, "acceptedByKeyId")
        requireNonEmpty(drivePermissionId, "drivePermissionId")
        val verifiedInvitation = verifySharingInvitationV1(invitation, options)
        val verifiedResponse = verifySharingPublicKeyResponseV1(response)
        if (
            verifiedResponse.appId != verifiedInvitation.appId ||
            verifiedResponse.exchangeId != verifiedInvitation.exchangeId
        ) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "The public-key response does not match this invitation.",
            )
        }
        if (drivePermissionId != verifiedInvitation.recipientDrivePermissionId) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "The response Drive account does not match the invited account.",
            )
        }
        val accepted = SharingAcceptanceProvenanceV1(
            exchangeId = verifiedInvitation.exchangeId,
            drivePermissionId = drivePermissionId,
            acceptedAt = options.now().toInstant().toString(),
            acceptedByKeyId = acceptedByKeyId,
            googleSubject = googleSubject,
        )
        return verifiedInvitation.requestedGrants.map { grant ->
            AcceptedSharingGrantV1(
                datasetId = grant.datasetId,
                participant = SharedBackupParticipantInput(
                    publicKey = publicKeyFromResponse(verifiedResponse),
                    role = grant.role,
                    accepted = accepted,
                ),
            )
        }
    }

    fun <T> createSharedBackupEnvelopeV1(
        value: T,
        codec: SharedBackupCodec<T>,
        identity: SharingIdentity,
        input: CreateSharedBackupEnvelopeInput,
        options: SharingCryptoOptions = SharingCryptoOptions(),
    ): SharedBackupEnvelopeV1 {
        requireNonEmpty(input.appId, "appId")
        requireNonEmpty(input.backupId, "backupId")
        assertIdentity(identity)
        input.keyRotationPreviousIdentity?.let { assertIdentity(it) }
        val participants = normalizedParticipants(input.participants)
        val author = participants.find { it.keyId == identity.publicKey.keyId }
            ?: throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "The author is not allowed to write this shared backup.",
            )
        if (!canWriteSharedBackup(author.role)) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "The author is not allowed to write this shared backup.",
            )
        }
        val previous = input.previous?.let { verifySharedBackupEnvelopeV1(it) }
        assertParticipantKeys(participants)
        assertRevisionAuthority(
            input.appId,
            input.backupId,
            participants,
            identity.publicKey.keyId,
            previous,
            input.keyRotationPreviousIdentity?.publicKey?.keyId,
        )
        val accessControl = createAccessControl(
            input.appId,
            input.backupId,
            participants,
            identity,
            previous,
            input.keyRotationPreviousIdentity,
        )
        val revisionId = input.revisionId ?: options.randomUuid()
        val createdAt = input.createdAt ?: options.now().toInstant().toString()
        requireNonEmpty(revisionId, "revisionId")
        val header = buildJsonObject {
            put("schemaVersion", 1)
            put("kind", SHARED_BACKUP_KIND)
            put("algorithm", SHARING_CONTENT_ALGORITHM)
            put("appId", input.appId)
            put("backupId", input.backupId)
            put("revisionId", revisionId)
            previous?.let { put("parentRevisionId", it.revisionId) }
            previous?.let {
                val ancestors = (it.revisionAncestors.orEmpty() + it.revisionId)
                    .takeLast(SHARED_BACKUP_MAX_REVISION_ANCESTORS)
                put(
                    "revisionAncestors",
                    SyncKitJson.instance.encodeToJsonElement(
                        kotlinx.serialization.builtins.ListSerializer(kotlinx.serialization.serializer()),
                        ancestors,
                    ),
                )
            }
            put("createdAt", createdAt)
            put("authorKeyId", identity.publicKey.keyId)
        }
        val rawContentKey = options.randomBytes(32)
        try {
            val payloadNonce = options.randomBytes(12)
            val serialized = try {
                codec.serialize(value)
            } catch (error: Exception) {
                throw SyncKitError(
                    SyncKitErrorCode.COMPATIBILITY,
                    "Shared-backup serialization failed.",
                    error,
                )
            }
            val ciphertext = SharingEcKeys.encryptAesGcm(
                rawContentKey,
                payloadNonce,
                CanonicalJson.encodeAad(header),
                SyncKitJson.instance.encodeToString(JsonElement.serializer(), serialized)
                    .toByteArray(Charsets.UTF_8),
            )
            val keyGrants = participants.map { participant ->
                createKeyGrant(rawContentKey, header, participant, options)
            }
            val unsigned = buildJsonObject {
                header.forEach { (key, value) -> put(key, value) }
                put(
                    "accessControl",
                    SyncKitJson.instance.encodeToJsonElement(
                        kotlinx.serialization.builtins.ListSerializer(SharedBackupAccessV1.serializer()),
                        accessControl,
                    ),
                )
                put(
                    "keyGrants",
                    SyncKitJson.instance.encodeToJsonElement(
                        kotlinx.serialization.builtins.ListSerializer(SharedBackupKeyGrantV1.serializer()),
                        keyGrants,
                    ),
                )
                put("payloadNonce", Base64Url.encode(payloadNonce))
                put("ciphertext", Base64Url.encode(ciphertext))
            }
            val signature = SharingEcKeys.sign(
                identity.signingPrivateKey,
                CanonicalJson.encodeAad(unsigned),
            )
            return parseSharedBackupEnvelopeV1(
                SyncKitJson.instance.decodeFromJsonElement(
                    SharedBackupEnvelopeV1.serializer(),
                    buildJsonObject {
                        unsigned.forEach { (key, value) -> put(key, value) }
                        put("signature", Base64Url.encode(signature))
                    },
                ),
            )
        } finally {
            rawContentKey.fill(0)
        }
    }

    private fun unwrapContentKey(
        grant: SharedBackupKeyGrantV1,
        header: JsonElement,
        privateKey: ECPrivateKey,
    ): ByteArray {
        val grantHeader = buildJsonObject {
            put("appId", (header as JsonObject)["appId"]!!)
            put("backupId", header["backupId"]!!)
            put("revisionId", header["revisionId"]!!)
            put("recipientKeyId", grant.recipientKeyId)
            put("ephemeralPublicKey", grant.ephemeralPublicKey)
            put("kdfSalt", grant.kdfSalt)
            put("nonce", grant.nonce)
        }
        val wrappingKey = deriveWrappingKey(
            privateKey,
            SharingEcKeys.publicKeyFromUncompressed(Base64Url.decode(grant.ephemeralPublicKey)),
            Base64Url.decode(grant.kdfSalt),
            grantHeader,
        )
        return SharingEcKeys.decryptAesGcm(
            wrappingKey,
            Base64Url.decode(grant.nonce),
            CanonicalJson.encodeAad(grantHeader),
            Base64Url.decode(grant.wrappedContentKey),
        )
    }

    private fun deriveWrappingKey(
        privateKey: ECPrivateKey,
        publicKey: PublicKey,
        salt: ByteArray,
        context: JsonElement,
    ): ByteArray {
        val secret = SharingEcKeys.ecdh(privateKey, publicKey)
        try {
            val info = ("sync-kit-sharing-v1:" + CanonicalJson.encode(context))
                .toByteArray(Charsets.UTF_8)
            return SharingEcKeys.hkdf(secret, salt, info, 32)
        } finally {
            secret.fill(0)
        }
    }

    private fun createKeyGrant(
        rawContentKey: ByteArray,
        header: JsonElement,
        participant: SharedBackupParticipantV1,
        options: SharingCryptoOptions,
    ): SharedBackupKeyGrantV1 {
        val ephemeral = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val ephemeralPublicKey = SharingEcKeys.exportUncompressedPublicKey(ephemeral.public)
        val kdfSalt = options.randomBytes(32)
        val nonce = options.randomBytes(12)
        val grantHeader = buildJsonObject {
            put("appId", (header as JsonObject)["appId"]!!)
            put("backupId", header["backupId"]!!)
            put("revisionId", header["revisionId"]!!)
            put("recipientKeyId", participant.keyId)
            put("ephemeralPublicKey", ephemeralPublicKey)
            put("kdfSalt", Base64Url.encode(kdfSalt))
            put("nonce", Base64Url.encode(nonce))
        }
        val wrappingKey = deriveWrappingKey(
            ephemeral.private as ECPrivateKey,
            SharingEcKeys.encryptionPublicKey(participant),
            kdfSalt,
            grantHeader,
        )
        val wrappedContentKey = SharingEcKeys.encryptAesGcm(
            wrappingKey,
            nonce,
            CanonicalJson.encodeAad(grantHeader),
            rawContentKey,
        )
        return SharedBackupKeyGrantV1(
            recipientKeyId = participant.keyId,
            ephemeralPublicKey = ephemeralPublicKey,
            kdfSalt = Base64Url.encode(kdfSalt),
            nonce = Base64Url.encode(nonce),
            wrappedContentKey = Base64Url.encode(wrappedContentKey),
        )
    }

    private fun createAccessControl(
        appId: String,
        backupId: String,
        participants: List<SharedBackupParticipantV1>,
        identity: SharingIdentity,
        previous: SharedBackupEnvelopeV1?,
        previousIdentity: SharingIdentity?,
    ): List<SharedBackupAccessV1> {
        if (
            previous != null &&
            CanonicalJson.encode(
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                    sharedBackupParticipants(previous),
                ),
            ) == CanonicalJson.encode(
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                    participants,
                ),
            )
        ) {
            return previous.accessControl
        }
        val priorEntry = previous?.accessControl?.lastOrNull()
        val sequence = previous?.accessControl?.size ?: 0
        val previousHash = priorEntry?.let { accessControlHash(it) }
        val rotationUnsigned = previousIdentity?.let {
            buildJsonObject {
                put("appId", appId)
                put("backupId", backupId)
                put("sequence", sequence)
                previousHash?.let { hash -> put("previousHash", hash) }
                put("fromKeyId", it.publicKey.keyId)
                put("toKeyId", identity.publicKey.keyId)
                put(
                    "participants",
                    SyncKitJson.instance.encodeToJsonElement(
                        kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                        participants,
                    ),
                )
            }
        }
        val keyRotation = previousIdentity?.let {
            SharedBackupKeyRotationV1(
                fromKeyId = it.publicKey.keyId,
                toKeyId = identity.publicKey.keyId,
                newKeyProof = Base64Url.encode(
                    SharingEcKeys.sign(
                        identity.signingPrivateKey,
                        CanonicalJson.encodeAad(rotationUnsigned!!),
                    ),
                ),
            )
        }
        val accessSigner = previousIdentity ?: identity
        val unsigned = buildJsonObject {
            put("appId", appId)
            put("backupId", backupId)
            put("sequence", sequence)
            previousHash?.let { put("previousHash", it) }
            put("authorKeyId", accessSigner.publicKey.keyId)
            put(
                "participants",
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                    participants,
                ),
            )
            keyRotation?.let { rotation ->
                put(
                    "keyRotation",
                    SyncKitJson.instance.encodeToJsonElement(
                        SharedBackupKeyRotationV1.serializer(),
                        rotation,
                    ),
                )
            }
        }
        val entry = SharedBackupAccessV1(
            appId = appId,
            backupId = backupId,
            sequence = sequence,
            previousHash = previousHash,
            authorKeyId = accessSigner.publicKey.keyId,
            participants = participants,
            keyRotation = keyRotation,
            signature = Base64Url.encode(
                SharingEcKeys.sign(
                    accessSigner.signingPrivateKey,
                    CanonicalJson.encodeAad(unsigned),
                ),
            ),
        )
        return (previous?.accessControl.orEmpty()) + entry
    }

    private fun verifyAccessControl(
        accessControl: List<SharedBackupAccessV1>,
        trustedOwnerKeyId: String?,
        appId: String,
        backupId: String,
    ): List<SharedBackupParticipantV1> {
        var previous: SharedBackupAccessV1? = null
        var ownerKeyId: String? = null
        for (entry in accessControl) {
            if (
                (entry.appId != null || entry.backupId != null) &&
                (entry.appId != appId || entry.backupId != backupId)
            ) {
                throw SyncKitError(
                    SyncKitErrorCode.AUTHORIZATION,
                    "An access-control entry belongs to another dataset.",
                )
            }
            assertParticipantKeys(entry.participants)
            val owner = entry.participants.find { it.role == SharingRole.OWNER }
                ?: throw SyncKitError(
                    SyncKitErrorCode.AUTHORIZATION,
                    "An access-control entry has no owner.",
                )
            if (ownerKeyId == null) {
                ownerKeyId = owner.keyId
                if (trustedOwnerKeyId != null && trustedOwnerKeyId != ownerKeyId) {
                    throw SyncKitError(
                        SyncKitErrorCode.AUTHORIZATION,
                        "The shared backup does not match the trusted owner key.",
                    )
                }
            }
            val author: SharedBackupParticipantV1?
            val validRotation: Boolean
            if (previous != null) {
                val expectedHash = accessControlHash(previous)
                if (entry.previousHash != expectedHash) {
                    throw SyncKitError(
                        SyncKitErrorCode.CRYPTO,
                        "The access-control history hash is invalid.",
                    )
                }
                author = previous.participants.find { it.keyId == entry.authorKeyId }
                validRotation = entry.keyRotation?.let {
                    verifyAccessKeyRotation(entry, previous)
                } ?: false
                if (author == null || (!canAdministerSharedBackup(author.role) && !validRotation)) {
                    throw SyncKitError(
                        SyncKitErrorCode.AUTHORIZATION,
                        "An access-control change was not signed by a prior owner or admin.",
                    )
                }
                if (owner.keyId != ownerKeyId) {
                    val rotation = entry.keyRotation
                    if (
                        !validRotation ||
                        rotation?.fromKeyId != ownerKeyId ||
                        rotation.toKeyId != owner.keyId
                    ) {
                        throw SyncKitError(
                            SyncKitErrorCode.AUTHORIZATION,
                            "Owner transfer is not supported by sharing v1.",
                        )
                    }
                    ownerKeyId = owner.keyId
                }
            } else {
                if (entry.keyRotation != null) {
                    throw SyncKitError(
                        SyncKitErrorCode.AUTHORIZATION,
                        "A genesis access entry cannot rotate a key.",
                    )
                }
                author = entry.participants.find { it.keyId == entry.authorKeyId }
                if (author?.role != SharingRole.OWNER) {
                    throw SyncKitError(
                        SyncKitErrorCode.AUTHORIZATION,
                        "The first access-control entry was not signed by its owner.",
                    )
                }
            }
            val unsigned = accessEntryJsonWithoutSignature(entry)
            if (!SharingEcKeys.verify(
                    SharingEcKeys.signingPublicKey(author!!),
                    CanonicalJson.encodeAad(unsigned),
                    Base64Url.decode(entry.signature),
                )
            ) {
                throw SyncKitError(
                    SyncKitErrorCode.CRYPTO,
                    "An access-control signature is invalid.",
                )
            }
            previous = entry
        }
        return previous?.participants
            ?: throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "Access-control history is empty.",
            )
    }

    private fun verifyAccessKeyRotation(
        entry: SharedBackupAccessV1,
        previous: SharedBackupAccessV1,
    ): Boolean {
        val rotation = entry.keyRotation ?: return false
        if (entry.appId.isNullOrBlank() || entry.backupId.isNullOrBlank() ||
            entry.authorKeyId != rotation.fromKeyId
        ) {
            return false
        }
        val from = previous.participants.find { it.keyId == rotation.fromKeyId } ?: return false
        val to = entry.participants.find { it.keyId == rotation.toKeyId } ?: return false
        if (
            !canWriteSharedBackup(from.role) ||
            from.role != to.role ||
            CanonicalJson.encode(acceptanceJson(from.accepted)) !=
            CanonicalJson.encode(acceptanceJson(to.accepted))
        ) {
            return false
        }
        val expectedParticipants = previous.participants
            .map { if (it.keyId == from.keyId) to else it }
            .sortedWith { left, right ->
                CanonicalJson.compareUtf16CodeUnits(left.keyId, right.keyId)
            }
        if (
            CanonicalJson.encode(
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                    expectedParticipants,
                ),
            ) != CanonicalJson.encode(
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                    entry.participants,
                ),
            )
        ) {
            return false
        }
        val proof = buildJsonObject {
            put("appId", entry.appId!!)
            put("backupId", entry.backupId!!)
            put("sequence", entry.sequence)
            entry.previousHash?.let { put("previousHash", it) }
            put("fromKeyId", rotation.fromKeyId)
            put("toKeyId", rotation.toKeyId)
            put(
                "participants",
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                    entry.participants,
                ),
            )
        }
        return SharingEcKeys.verify(
            SharingEcKeys.signingPublicKey(to),
            CanonicalJson.encodeAad(proof),
            Base64Url.decode(rotation.newKeyProof),
        )
    }

    private fun accessControlHash(entry: SharedBackupAccessV1): String =
        Base64Url.encode(
            SharingEcKeys.digestSha256(
                CanonicalJson.encodeAad(
                    SyncKitJson.instance.encodeToJsonElement(
                        SharedBackupAccessV1.serializer(),
                        entry,
                    ),
                ),
            ),
        )

    private fun assertIdentity(identity: SharingIdentity) {
        val expected = SharingEcKeys.createSharingPublicKeyV1(
            identity.publicKey.encryptionPublicKey,
            identity.publicKey.signingPublicKey,
        )
        if (expected.keyId != identity.publicKey.keyId) {
            throw SyncKitError(
                SyncKitErrorCode.KEY,
                "The sharing identity fingerprint is invalid.",
            )
        }
    }

    private fun assertParticipantKeys(participants: List<SharedBackupParticipantV1>) {
        for (participant in participants) {
            val expected = SharingEcKeys.createSharingPublicKeyV1(
                participant.encryptionPublicKey,
                participant.signingPublicKey,
            )
            if (expected.keyId != participant.keyId) {
                throw SyncKitError(
                    SyncKitErrorCode.KEY,
                    "Participant fingerprint ${participant.keyId} is invalid.",
                )
            }
        }
    }

    private fun assertRevisionAuthority(
        appId: String,
        backupId: String,
        participants: List<SharedBackupParticipantV1>,
        authorKeyId: String,
        previous: SharedBackupEnvelopeV1?,
        rotationFromKeyId: String?,
    ) {
        if (previous == null) {
            val owner = participants.find { it.role == SharingRole.OWNER }
            if (owner?.keyId != authorKeyId) {
                throw SyncKitError(
                    SyncKitErrorCode.AUTHORIZATION,
                    "Only the owner can create the first shared-backup revision.",
                )
            }
            return
        }
        if (previous.appId != appId || previous.backupId != backupId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The previous revision belongs to a different shared backup.",
            )
        }
        val priorAuthor = sharedBackupParticipant(previous, rotationFromKeyId ?: authorKeyId)
        if (priorAuthor == null || !canWriteSharedBackup(priorAuthor.role)) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "The previous revision does not authorize this writer.",
            )
        }
        val participantsChanged =
            CanonicalJson.encode(
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                    sharedBackupParticipants(previous),
                ),
            ) != CanonicalJson.encode(
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                    participants,
                ),
            )
        if (participantsChanged && rotationFromKeyId == null &&
            !canAdministerSharedBackup(priorAuthor.role)
        ) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "Only an owner or admin can change shared-backup participants.",
            )
        }
        val priorOwner = sharedBackupParticipants(previous).find { it.role == SharingRole.OWNER }
        val nextOwner = participants.find { it.role == SharingRole.OWNER }
        if (priorOwner?.keyId != nextOwner?.keyId &&
            (rotationFromKeyId != priorOwner?.keyId || authorKeyId != nextOwner?.keyId)
        ) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "Owner transfer is not supported by sharing v1.",
            )
        }
        if (rotationFromKeyId != null) {
            val replacement = participants.find { it.keyId == authorKeyId }
            val expected = sharedBackupParticipants(previous)
                .map { if (it.keyId == rotationFromKeyId) replacement else it }
                .filterNotNull()
                .sortedWith { left, right ->
                    CanonicalJson.compareUtf16CodeUnits(left.keyId, right.keyId)
                }
            if (
                replacement?.role != priorAuthor.role ||
                CanonicalJson.encode(acceptanceJson(replacement.accepted)) !=
                CanonicalJson.encode(acceptanceJson(priorAuthor.accepted)) ||
                CanonicalJson.encode(
                    SyncKitJson.instance.encodeToJsonElement(
                        kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                        expected,
                    ),
                ) != CanonicalJson.encode(
                    SyncKitJson.instance.encodeToJsonElement(
                        kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                        participants,
                    ),
                )
            ) {
                throw SyncKitError(
                    SyncKitErrorCode.AUTHORIZATION,
                    "A key rotation may only replace the current writer's key.",
                )
            }
        }
    }

    private fun normalizedParticipants(
        input: List<SharedBackupParticipantInput>,
    ): List<SharedBackupParticipantV1> {
        if (input.isEmpty()) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "participants must not be empty.",
            )
        }
        val participants = input
            .map { (publicKey, role, accepted) ->
                SharedBackupParticipantV1(
                    keyId = publicKey.keyId,
                    encryptionAlgorithm = publicKey.encryptionAlgorithm,
                    encryptionPublicKey = publicKey.encryptionPublicKey,
                    signatureAlgorithm = publicKey.signatureAlgorithm,
                    signingPublicKey = publicKey.signingPublicKey,
                    role = role,
                    accepted = accepted,
                )
            }
            .sortedWith { left, right ->
                CanonicalJson.compareUtf16CodeUnits(left.keyId, right.keyId)
            }
        if (participants.distinctBy { it.keyId }.size != participants.size) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "Duplicate participant key IDs.",
            )
        }
        if (participants.count { it.role == SharingRole.OWNER } != 1) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "A shared backup must have exactly one owner.",
            )
        }
        return participants
    }

    private fun normalizedRequestedGrants(
        input: List<SharingDatasetGrantV1>,
    ): List<SharingDatasetGrantV1> {
        if (input.isEmpty()) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "requestedGrants must not be empty.",
            )
        }
        val grants = input.sortedWith { left, right ->
            CanonicalJson.compareUtf16CodeUnits(left.datasetId, right.datasetId)
        }
        grants.forEachIndexed { index, grant ->
            requireNonEmpty(grant.datasetId, "datasetId")
            if (index > 0 && grants[index - 1].datasetId == grant.datasetId) {
                throw SyncKitError(
                    SyncKitErrorCode.CONFIGURATION,
                    "Duplicate requested dataset ${grant.datasetId}.",
                )
            }
        }
        return grants
    }

    private fun publicKeyFromResponse(response: SharingPublicKeyResponseV1): SharingPublicKeyV1 =
        SharingPublicKeyV1(
            keyId = response.keyId,
            encryptionAlgorithm = response.encryptionAlgorithm,
            encryptionPublicKey = response.encryptionPublicKey,
            signatureAlgorithm = response.signatureAlgorithm,
            signingPublicKey = response.signingPublicKey,
        )

    private fun sharedBackupHeaderJson(envelope: SharedBackupEnvelopeV1): JsonElement =
        buildJsonObject {
            put("schemaVersion", envelope.schemaVersion)
            put("kind", envelope.kind)
            put("algorithm", envelope.algorithm)
            put("appId", envelope.appId)
            put("backupId", envelope.backupId)
            put("revisionId", envelope.revisionId)
            envelope.parentRevisionId?.let { put("parentRevisionId", it) }
            envelope.revisionAncestors?.let { ancestors ->
                put(
                    "revisionAncestors",
                    SyncKitJson.instance.encodeToJsonElement(
                        kotlinx.serialization.builtins.ListSerializer(kotlinx.serialization.serializer()),
                        ancestors,
                    ),
                )
            }
            put("createdAt", envelope.createdAt)
            put("authorKeyId", envelope.authorKeyId)
        }

    private fun envelopeJsonWithoutSignature(envelope: SharedBackupEnvelopeV1): JsonElement =
        buildJsonObject {
            put("schemaVersion", envelope.schemaVersion)
            put("kind", envelope.kind)
            put("algorithm", envelope.algorithm)
            put("appId", envelope.appId)
            put("backupId", envelope.backupId)
            put("revisionId", envelope.revisionId)
            envelope.parentRevisionId?.let { put("parentRevisionId", it) }
            envelope.revisionAncestors?.let { ancestors ->
                put(
                    "revisionAncestors",
                    SyncKitJson.instance.encodeToJsonElement(
                        kotlinx.serialization.builtins.ListSerializer(kotlinx.serialization.serializer()),
                        ancestors,
                    ),
                )
            }
            put("createdAt", envelope.createdAt)
            put("authorKeyId", envelope.authorKeyId)
            put(
                "accessControl",
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupAccessV1.serializer()),
                    envelope.accessControl,
                ),
            )
            put(
                "keyGrants",
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupKeyGrantV1.serializer()),
                    envelope.keyGrants,
                ),
            )
            put("payloadNonce", envelope.payloadNonce)
            put("ciphertext", envelope.ciphertext)
        }

    private fun invitationJsonWithoutSignature(invitation: SharingInvitationV1): JsonElement =
        buildJsonObject {
            put("schemaVersion", invitation.schemaVersion)
            put("kind", invitation.kind)
            put("appId", invitation.appId)
            put("appFolderId", invitation.appFolderId)
            put("exchangeId", invitation.exchangeId)
            put("recipientDrivePermissionId", invitation.recipientDrivePermissionId)
            put(
                "requestedGrants",
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharingDatasetGrantV1.serializer()),
                    invitation.requestedGrants,
                ),
            )
            put("trustedOwnerKeyId", invitation.trustedOwnerKeyId)
            put("createdAt", invitation.createdAt)
            invitation.expiresAt?.let { put("expiresAt", it) }
            put(
                "owner",
                SyncKitJson.instance.encodeToJsonElement(
                    SharingPublicKeyV1.serializer(),
                    invitation.owner,
                ),
            )
        }

    private fun responseJsonWithoutProof(response: SharingPublicKeyResponseV1): JsonElement =
        buildJsonObject {
            put("schemaVersion", response.schemaVersion)
            put("kind", response.kind)
            put("appId", response.appId)
            put("exchangeId", response.exchangeId)
            put("createdAt", response.createdAt)
            put("keyId", response.keyId)
            put("encryptionAlgorithm", response.encryptionAlgorithm)
            put("encryptionPublicKey", response.encryptionPublicKey)
            put("signatureAlgorithm", response.signatureAlgorithm)
            put("signingPublicKey", response.signingPublicKey)
            response.accountBinding?.let { binding ->
                put(
                    "accountBinding",
                    SyncKitJson.instance.encodeToJsonElement(
                        SharingAccountBindingV1.serializer(),
                        binding,
                    ),
                )
            }
        }

    private fun accessEntryJsonWithoutSignature(entry: SharedBackupAccessV1): JsonElement =
        buildJsonObject {
            entry.appId?.let { put("appId", it) }
            entry.backupId?.let { put("backupId", it) }
            put("sequence", entry.sequence)
            entry.previousHash?.let { put("previousHash", it) }
            put("authorKeyId", entry.authorKeyId)
            put(
                "participants",
                SyncKitJson.instance.encodeToJsonElement(
                    kotlinx.serialization.builtins.ListSerializer(SharedBackupParticipantV1.serializer()),
                    entry.participants,
                ),
            )
            entry.keyRotation?.let { rotation ->
                put(
                    "keyRotation",
                    SyncKitJson.instance.encodeToJsonElement(
                        SharedBackupKeyRotationV1.serializer(),
                        rotation,
                    ),
                )
            }
        }

    private fun acceptanceJson(accepted: SharingAcceptanceProvenanceV1?): JsonElement =
        accepted?.let {
            SyncKitJson.instance.encodeToJsonElement(
                SharingAcceptanceProvenanceV1.serializer(),
                it,
            )
        } ?: kotlinx.serialization.json.JsonNull

    private fun requireNonEmpty(value: String, name: String) {
        if (value.isBlank()) throw IllegalArgumentException("$name must not be empty.")
    }
}

data class VerifySharedBackupOptions(
    val trustedOwnerKeyId: String? = null,
)

data class CreateSharingInvitationInput(
    val appId: String,
    val appFolderId: String,
    val recipientDrivePermissionId: String,
    val requestedGrants: List<SharingDatasetGrantV1>,
    val trustedOwnerKeyId: String? = null,
    val exchangeId: String? = null,
    val expiresAt: String? = null,
)

data class CreateSharedBackupEnvelopeInput(
    val appId: String,
    val backupId: String,
    val participants: List<SharedBackupParticipantInput>,
    val previous: SharedBackupEnvelopeV1? = null,
    val keyRotationPreviousIdentity: SharingIdentity? = null,
    val revisionId: String? = null,
    val createdAt: String? = null,
)
