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

class SyncKitCompatibilityException(message: String) : Exception(message)
