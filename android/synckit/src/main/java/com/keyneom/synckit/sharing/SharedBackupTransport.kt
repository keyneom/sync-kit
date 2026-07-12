package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.sharing.checkpoint.SharedDatasetHead

data class SharedBackupStorage(
    val appFolderId: String,
    val exchangesFolderId: String,
)

data class SharedDatasetFile(
    val datasetId: String,
    val fileId: String,
    val name: String,
    val canEdit: Boolean? = null,
)

data class VersionedSharedDataset(
    val datasetId: String,
    val fileId: String,
    val name: String,
    val canEdit: Boolean? = null,
    val envelope: SharedBackupEnvelopeV1,
    val version: String,
)

data class SharedExchangeFile(
    val fileId: String,
    val exchangeId: String,
    val kind: String,
    val keyId: String? = null,
    val createdTime: String? = null,
)

data class SharedKeyResponseFile(
    val fileId: String,
    val response: SharingPublicKeyResponseV1,
    val ownerPermissionId: String,
)

data class SharedDatasetPermission(
    val permissionId: String? = null,
    val role: String,
)

data class SharedDatasetDrivePermission(
    val permissionId: String,
    val role: String,
    val emailAddress: String? = null,
    val inherited: Boolean = false,
)

interface SharedBackupTransport {
    suspend fun ensureStorage(): SharedBackupStorage
    suspend fun listDatasets(): List<SharedDatasetFile>
    suspend fun readDataset(fileId: String): VersionedSharedDataset
    suspend fun createDataset(
        datasetId: String,
        envelope: SharedBackupEnvelopeV1,
    ): VersionedSharedDataset
    suspend fun writeDataset(
        current: VersionedSharedDataset,
        envelope: SharedBackupEnvelopeV1,
    ): VersionedSharedDataset
    suspend fun deleteDataset(fileId: String): Unit = throw SyncKitError(
        SyncKitErrorCode.STATE,
        "This transport does not support deleting datasets.",
    )

    /**
     * Move a dataset file to the provider's trash instead of deleting it.
     * The recovery-safe disposal used when a topology migration closes and
     * retires its source file (docs/sharing-control-datasets.md).
     */
    suspend fun trashDataset(fileId: String): Unit = throw SyncKitError(
        SyncKitErrorCode.STATE,
        "This transport does not support trashing datasets.",
    )
    suspend fun grantExchangeAccess(
        emailAddress: String,
        sendNotificationEmail: Boolean? = null,
        emailMessage: String? = null,
    ): ExchangeAccessResult
    suspend fun createInvitation(invitation: SharingInvitationV1): String
    suspend fun createKeyResponse(response: SharingPublicKeyResponseV1): String
    suspend fun listExchanges(
        exchangeId: String? = null,
        kind: String? = null,
    ): List<SharedExchangeFile>
    suspend fun readInvitation(fileId: String): SharingInvitationV1
    suspend fun readKeyResponse(
        fileId: String,
        expectedDrivePermissionId: String,
    ): SharedKeyResponseFile
    suspend fun deleteExchange(fileId: String)
    suspend fun setDatasetPermission(
        fileId: String,
        emailAddress: String,
        role: SharingRole,
        existingDirectPermissionId: String? = null,
        hasInheritedReadAccess: Boolean = false,
    ): SharedDatasetPermission
    suspend fun removeDatasetPermission(fileId: String, permissionId: String)
    suspend fun listDatasetPermissions(fileId: String): List<SharedDatasetDrivePermission>
    suspend fun listDatasetHeads(): List<SharedDatasetHead>
}

data class ExchangeAccessResult(
    val drivePermissionId: String,
    val appFolderId: String,
)

data class SharedDatasetRegistryRecord(
    val datasetId: String,
    val fileId: String? = null,
    val trustedOwnerKeyId: String,
    val lastRevisionId: String? = null,
    val seenRevisionIds: List<String>? = null,
    val participantPermissionIds: Map<String, String>? = null,
)

interface SharedBackupRegistry {
    suspend fun get(datasetId: String): SharedDatasetRegistryRecord?
    suspend fun set(record: SharedDatasetRegistryRecord)
    suspend fun delete(datasetId: String)
}

class MemorySharedBackupRegistry : SharedBackupRegistry {
    private val records = mutableMapOf<String, SharedDatasetRegistryRecord>()

    override suspend fun get(datasetId: String): SharedDatasetRegistryRecord? =
        records[datasetId]?.copy(
            seenRevisionIds = records[datasetId]?.seenRevisionIds?.toList(),
            participantPermissionIds = records[datasetId]?.participantPermissionIds?.toMap(),
        )

    override suspend fun set(record: SharedDatasetRegistryRecord) {
        records[record.datasetId] = record.copy(
            seenRevisionIds = record.seenRevisionIds?.toList(),
            participantPermissionIds = record.participantPermissionIds?.toMap(),
        )
    }

    override suspend fun delete(datasetId: String) {
        records.remove(datasetId)
    }
}
