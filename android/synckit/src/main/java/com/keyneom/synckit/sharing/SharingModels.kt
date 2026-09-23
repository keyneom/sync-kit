package com.keyneom.synckit.sharing

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

const val SHARING_KEY_KIND = "sync-kit-public-key"
const val SHARING_INVITATION_KIND = "sync-kit-share-invitation"
const val SHARING_OWNERSHIP_TRANSFER_KIND = "sync-kit-ownership-transfer"
const val SHARED_BACKUP_KIND = "sync-kit-shared-backup"
const val SHARING_ENCRYPTION_ALGORITHM = "ECDH-P256"
const val SHARING_SIGNATURE_ALGORITHM = "ECDSA-P256-SHA256-P1363"
const val SHARING_CONTENT_ALGORITHM = "AES-256-GCM+ECDH-P256+HKDF-SHA256"
const val SHARED_BACKUP_MAX_REVISION_ANCESTORS = 256

/** Upper bound on additional keys one participant may hold in a dataset. */
const val SHARED_BACKUP_MAX_ADDITIONAL_KEYS_PER_PARTICIPANT = 8
const val PARTICIPANT_KEY_ADDITION_KIND = "sync-kit-participant-key-addition"
const val PARTICIPANT_KEY_REMOVAL_KIND = "sync-kit-participant-key-removal"
const val PARTICIPANT_KEY_ROTATION_KIND = "sync-kit-participant-key-rotation"
const val SHARING_PROTOCOL = "sharing-v1"

@Serializable
enum class SharingRole {
    @SerialName("owner") OWNER,
    @SerialName("admin") ADMIN,
    @SerialName("writer") WRITER,
    @SerialName("viewer") VIEWER,
}

@Serializable
data class SharingPublicKeyV1(
    val keyId: String,
    val encryptionAlgorithm: String,
    val encryptionPublicKey: String,
    val signatureAlgorithm: String,
    val signingPublicKey: String,
)

@Serializable
data class SharingPublicKeyResponseV1(
    val schemaVersion: Int,
    val kind: String,
    val appId: String,
    val exchangeId: String,
    val createdAt: String,
    val keyId: String,
    val encryptionAlgorithm: String,
    val encryptionPublicKey: String,
    val signatureAlgorithm: String,
    val signingPublicKey: String,
    val proof: String,
    val accountBinding: SharingAccountBindingV1? = null,
)

@Serializable
data class SharingAccountBindingV1(
    val schemaVersion: Int,
    val kind: String,
    val challenge: String,
    val googleIdToken: String,
    val passkey: SharingPasskeyAssertionV1,
)

@Serializable
data class SharingPasskeyAssertionV1(
    val credentialId: String,
    val credentialPublicKey: kotlinx.serialization.json.JsonObject,
    val authenticatorData: String,
    val clientDataJSON: String,
    val signature: String,
)

@Serializable
data class SharingDatasetGrantV1(
    val datasetId: String,
    val role: SharingRole,
)

@Serializable
data class SharingInvitationV1(
    val schemaVersion: Int,
    val kind: String,
    val appId: String,
    val appFolderId: String,
    val exchangeId: String,
    val recipientDrivePermissionId: String,
    val requestedGrants: List<SharingDatasetGrantV1>,
    val trustedOwnerKeyId: String,
    val createdAt: String,
    val expiresAt: String? = null,
    val owner: SharingPublicKeyV1,
    val signature: String,
)

@Serializable
data class SharingAcceptanceProvenanceV1(
    val exchangeId: String,
    val drivePermissionId: String,
    val acceptedAt: String,
    val acceptedByKeyId: String,
    val googleSubject: String? = null,
)

@Serializable
data class SharedBackupParticipantV1(
    val keyId: String,
    val encryptionAlgorithm: String,
    val encryptionPublicKey: String,
    val signatureAlgorithm: String,
    val signingPublicKey: String,
    val role: SharingRole,
    val accepted: SharingAcceptanceProvenanceV1? = null,
)

@Serializable
data class SharedBackupKeyRotationV1(
    val fromKeyId: String,
    val toKeyId: String,
    val newKeyProof: String,
    /**
     * Present when an additional key of [fromKeyId]'s participant authorized the
     * rotation — replacing a lost primary key. [newKeyProof] then signs the
     * app-scoped rotation statement instead of the entry.
     */
    val authorizedByKeyId: String? = null,
    val authorization: String? = null,
)

/**
 * A recovery key's private keys, sealed under a key derived from a generated
 * recovery code and stored in the dataset itself. See docs/participant-keys.md.
 */
@Serializable
data class SharedBackupSealedKeyV1(
    val kdf: String,
    val kdfSalt: String,
    val nonce: String,
    val encryptedPrivateKeys: String,
)

/**
 * A key a participant (its principal) holds in addition to its primary key. It
 * receives the content key on every revision and acts only for its principal,
 * never with a role of its own. See docs/participant-keys.md.
 */
@Serializable
data class SharedBackupAdditionalKeyV1(
    val keyId: String,
    val encryptionAlgorithm: String,
    val encryptionPublicKey: String,
    val signatureAlgorithm: String,
    val signingPublicKey: String,
    val principalKeyId: String,
    /** `recovery` or `device`. Informational; the rules are identical. */
    val purpose: String,
    val addedByKeyId: String,
    /** Signature by [addedByKeyId], a key of the principal, over the addition. */
    val addition: String,
    /** Signature by this key over the addition: proves the holder has it. */
    val possession: String,
    val sealedPrivateKeys: SharedBackupSealedKeyV1? = null,
) {
    val publicKey: SharingPublicKeyV1
        get() = SharingPublicKeyV1(
            keyId = keyId,
            encryptionAlgorithm = encryptionAlgorithm,
            encryptionPublicKey = encryptionPublicKey,
            signatureAlgorithm = signatureAlgorithm,
            signingPublicKey = signingPublicKey,
        )
}

/** Proof that a principal removed one of its own additional keys. */
@Serializable
data class SharedBackupKeyRemovalV1(
    val keyId: String,
    val removedByKeyId: String,
    val removal: String,
)

/**
 * A participant's signed request to replace its primary key, authorized by one
 * of its additional keys. [to] carries the replacement's public key so any
 * writer can apply it.
 */
@Serializable
data class SharedBackupAuthorizedKeyRotationV1(
    val fromKeyId: String,
    val to: SharingPublicKeyV1,
    val newKeyProof: String,
    val authorizedByKeyId: String,
    val authorization: String,
)

@Serializable
data class SharedBackupOwnershipTransferDatasetV1(
    val datasetId: String,
    val revisionId: String,
    val accessControlHash: String,
    val providerPermissionId: String,
)

@Serializable
data class SharedBackupOwnershipTransferProviderObjectV1(
    val kind: String,
    val fileId: String,
    val providerPermissionId: String,
)

@Serializable
data class SharedBackupOwnershipTransferV1(
    val schemaVersion: Int,
    val kind: String,
    val transferId: String,
    val appId: String,
    val fromKeyId: String,
    val toKeyId: String,
    val previousOwnerRole: SharingRole,
    val datasets: List<SharedBackupOwnershipTransferDatasetV1>,
    val providerObjects: List<SharedBackupOwnershipTransferProviderObjectV1>,
    val createdAt: String,
    val expiresAt: String? = null,
    val ownerProof: String,
    val newOwnerProof: String? = null,
)

@Serializable
data class SharedBackupAccessV1(
    val sequence: Int,
    val appId: String? = null,
    val backupId: String? = null,
    val previousHash: String? = null,
    val authorKeyId: String,
    val participants: List<SharedBackupParticipantV1>,
    val keyRotation: SharedBackupKeyRotationV1? = null,
    val ownershipTransfer: SharedBackupOwnershipTransferV1? = null,
    val signature: String,
    /** Opt-in per dataset. Null means no participant may hold additional keys. */
    val participantKeysPolicy: String? = null,
    val additionalKeys: List<SharedBackupAdditionalKeyV1>? = null,
    val removedAdditionalKeys: List<SharedBackupKeyRemovalV1>? = null,
)

@Serializable
data class SharedBackupKeyGrantV1(
    val recipientKeyId: String,
    val ephemeralPublicKey: String,
    val kdfSalt: String,
    val nonce: String,
    val wrappedContentKey: String,
)

@Serializable
data class SharedBackupEnvelopeV1(
    val schemaVersion: Int,
    val kind: String,
    val algorithm: String,
    val appId: String,
    val backupId: String,
    val revisionId: String,
    val parentRevisionId: String? = null,
    val revisionAncestors: List<String>? = null,
    val createdAt: String,
    val authorKeyId: String,
    val accessControl: List<SharedBackupAccessV1>,
    val keyGrants: List<SharedBackupKeyGrantV1>,
    val payloadNonce: String,
    val ciphertext: String,
    val signature: String,
)

interface SharedBackupCodec<T> {
    fun serialize(value: T): JsonElement
    fun parse(value: JsonElement): T
}

fun canReadSharedBackup(role: SharingRole): Boolean =
    role == SharingRole.OWNER ||
        role == SharingRole.ADMIN ||
        role == SharingRole.WRITER ||
        role == SharingRole.VIEWER

fun canWriteSharedBackup(role: SharingRole): Boolean =
    role == SharingRole.OWNER ||
        role == SharingRole.ADMIN ||
        role == SharingRole.WRITER

fun canAdministerSharedBackup(role: SharingRole): Boolean =
    role == SharingRole.OWNER || role == SharingRole.ADMIN

fun sharedBackupParticipants(envelope: SharedBackupEnvelopeV1): List<SharedBackupParticipantV1> {
    val participants = envelope.accessControl.lastOrNull()?.participants
        ?: throw SyncKitCompatibilityException("accessControl must not be empty.")
    return participants
}

fun sharedBackupParticipant(
    envelope: SharedBackupEnvelopeV1,
    keyId: String,
): SharedBackupParticipantV1? =
    sharedBackupParticipants(envelope).find { it.keyId == keyId }

/** Additional keys in the current revision. Empty unless the dataset opted in. */
fun sharedBackupAdditionalKeys(envelope: SharedBackupEnvelopeV1): List<SharedBackupAdditionalKeyV1> =
    envelope.accessControl.lastOrNull()?.additionalKeys.orEmpty()

/** Whether the dataset currently lets participants hold additional keys. */
fun sharedBackupParticipantKeysEnabled(envelope: SharedBackupEnvelopeV1): Boolean =
    envelope.accessControl.lastOrNull()?.participantKeysPolicy == PARTICIPANT_KEYS_ENABLED

/** A key that can read the current revision and the participant it acts for. */
data class SharedBackupKeyHolder(
    val participant: SharedBackupParticipantV1,
    val additionalKey: SharedBackupAdditionalKeyV1?,
)

/**
 * Resolves any key that can read the current revision to the participant it
 * acts for: a participant's own primary key, or one of its additional keys.
 */
fun sharedBackupKeyHolder(envelope: SharedBackupEnvelopeV1, keyId: String): SharedBackupKeyHolder? {
    sharedBackupParticipant(envelope, keyId)?.let { return SharedBackupKeyHolder(it, null) }
    val additionalKey = sharedBackupAdditionalKeys(envelope).find { it.keyId == keyId } ?: return null
    val principal = sharedBackupParticipant(envelope, additionalKey.principalKeyId) ?: return null
    return SharedBackupKeyHolder(principal, additionalKey)
}

/** Whether an access-control history has ever used participant keys (schemaVersion 2). */
fun accessControlUsesParticipantKeys(accessControl: List<SharedBackupAccessV1>): Boolean =
    accessControl.any { entry ->
        entry.participantKeysPolicy != null ||
            entry.additionalKeys != null ||
            entry.removedAdditionalKeys != null ||
            entry.keyRotation?.authorizedByKeyId != null
    }

const val PARTICIPANT_KEYS_ENABLED = "enabled"

class SyncKitCompatibilityException(message: String) : Exception(message)
