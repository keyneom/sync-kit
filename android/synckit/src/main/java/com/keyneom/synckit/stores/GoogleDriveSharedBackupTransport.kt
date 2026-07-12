package com.keyneom.synckit.stores

import android.util.Log
import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.core.AuthorizationProvider
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.sharing.SHARING_PROTOCOL
import com.keyneom.synckit.sharing.SharedBackupEnvelopeV1
import com.keyneom.synckit.sharing.SharedBackupTransport
import com.keyneom.synckit.sharing.SharedDatasetDrivePermission
import com.keyneom.synckit.sharing.SharedDatasetFile
import com.keyneom.synckit.sharing.SharedDatasetPermission
import com.keyneom.synckit.sharing.SharedExchangeFile
import com.keyneom.synckit.sharing.SharedKeyResponseFile
import com.keyneom.synckit.sharing.SharingCrypto
import com.keyneom.synckit.sharing.SharingInvitationV1
import com.keyneom.synckit.sharing.SharingPublicKeyResponseV1
import com.keyneom.synckit.sharing.SharingRole
import com.keyneom.synckit.sharing.SharedBackupStorage
import com.keyneom.synckit.sharing.VersionedSharedDataset
import com.keyneom.synckit.sharing.ExchangeAccessResult
import com.keyneom.synckit.sharing.checkpoint.SharedDatasetHead

private const val EXCHANGE_ID_PROPERTY = "sync-kit-exchange-id"
private const val KEY_ID_PROPERTY = "sync-kit-key-id"

class GoogleDriveSharedBackupTransport(
    private val appId: String,
    private val authorizationProvider: AuthorizationProvider,
    private val folderName: String? = null,
    private val parentFolderId: String? = null,
    private val selectedAppFolderId: String? = null,
    private val drive: GoogleDriveFileStore = GoogleDriveFileStore(),
) : SharedBackupTransport {
    init {
        require(appId.isNotBlank()) { "appId must not be empty." }
    }

    private var storagePromise: SharedBackupStorage? = null

    override suspend fun ensureStorage(): SharedBackupStorage {
        storagePromise?.let { return it }
        return ensureStorageNow().also { storagePromise = it }
    }

    override suspend fun listDatasets(): List<SharedDatasetFile> {
        val authorization = authorize()
        val storage = ensureStorage()
        val files = listAll(authorization, storage.appFolderId, properties("dataset"))
        return files.map { file ->
            SharedDatasetFile(
                datasetId = requiredProperty(file, SYNC_KIT_DATASET_ID_PROPERTY, "dataset"),
                fileId = file.fileId,
                name = file.name,
                canEdit = file.capabilities?.canEdit,
            )
        }
    }

    override suspend fun readDataset(fileId: String): VersionedSharedDataset {
        val authorization = authorize()
        val metadata = drive.get(fileId, authorization)
        assertManagedFile(metadata, "dataset")
        val datasetId = requiredProperty(metadata, SYNC_KIT_DATASET_ID_PROPERTY, "dataset")
        val document = drive.readTextVersioned(fileId, authorization)
        // Drive v3 rarely exposes HTTP ETags (never on Android's HTTP/2
        // connections), so fall back to the metadata change tokens. If-Match
        // is only usable with a real ETag; writeDataset compensates with a
        // pre-write freshness check when the token is not one.
        val version = document.etag ?: metadata.etag ?: metadata.headRevisionId
            ?: metadata.version
            ?: throw SyncKitError(
                SyncKitErrorCode.STATE,
                "Google Drive did not expose a change token for the dataset; a safe conditional write is unavailable.",
            )
        val envelope = SharingCrypto.parseSharedBackupEnvelopeV1(document.content)
        if (envelope.appId != appId || envelope.backupId != datasetId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The Drive dataset metadata does not match its encrypted envelope.",
            )
        }
        return VersionedSharedDataset(
            datasetId = datasetId,
            fileId = fileId,
            name = metadata.name,
            canEdit = metadata.capabilities?.canEdit,
            envelope = envelope,
            version = version,
        )
    }

    override suspend fun createDataset(
        datasetId: String,
        envelope: SharedBackupEnvelopeV1,
    ): VersionedSharedDataset {
        requireNonEmpty(datasetId, "datasetId")
        assertEnvelopeDataset(datasetId, envelope)
        val authorization = authorize()
        val storage = ensureStorage()
        val fileId = drive.create(
            name = "$datasetId.sync-kit.json",
            content = SyncKitJson.instance.encodeToString(
                SharedBackupEnvelopeV1.serializer(),
                envelope,
            ),
            authorization = authorization,
            parentId = storage.appFolderId,
            contentType = "application/json",
            appProperties = properties("dataset") + mapOf(SYNC_KIT_DATASET_ID_PROPERTY to datasetId),
        )
        return try {
            readDataset(fileId)
        } catch (error: Exception) {
            // Best-effort rollback: an orphan dataset would block every
            // future createDataset for this id with "already exists".
            runCatching { drive.delete(fileId, authorization) }
            throw error
        }
    }

    override suspend fun writeDataset(
        current: VersionedSharedDataset,
        envelope: SharedBackupEnvelopeV1,
    ): VersionedSharedDataset {
        assertEnvelopeDataset(current.datasetId, envelope)
        if (envelope.parentRevisionId != current.envelope.revisionId) {
            throw SyncKitError(
                SyncKitErrorCode.CONFLICT,
                "The new dataset revision does not descend from the version being replaced.",
            )
        }
        val authorization = authorize()
        val content = SyncKitJson.instance.encodeToString(
            SharedBackupEnvelopeV1.serializer(),
            envelope,
        )
        return try {
            val head = drive.getV2WriteHead(current.fileId, authorization)
            assertWriteHeadFresh(current.version, head)
            val written = drive.writeV2Media(
                fileId = current.fileId,
                content = content,
                authorization = authorization,
                contentType = "application/json",
                ifMatch = head.etag,
            )
            val version = written.headRevisionId
                ?: return readDataset(current.fileId)
            current.copy(envelope = envelope, version = version)
        } catch (error: DriveV2UnavailableException) {
            logDriveV2FallbackOnce()
            writeDatasetV3Fallback(current, envelope, content, authorization)
        }
    }

    private suspend fun writeDatasetV3Fallback(
        current: VersionedSharedDataset,
        envelope: SharedBackupEnvelopeV1,
        content: String,
        authorization: Authorization,
    ): VersionedSharedDataset {
        val ifMatch = current.version.takeIf { isHttpEtag(it) }
        if (ifMatch == null) {
            val head = drive.get(current.fileId, authorization)
            val headToken = head.etag ?: head.headRevisionId ?: head.version
            if (headToken != null && headToken != current.version) {
                throw SyncKitError(
                    SyncKitErrorCode.CONFLICT,
                    "The Drive dataset changed after it was last read.",
                )
            }
        }
        val written = drive.write(
            fileId = current.fileId,
            content = content,
            authorization = authorization,
            contentType = "application/json",
            ifMatch = ifMatch,
        )
        if (written.etag == null) return readDataset(current.fileId)
        return current.copy(envelope = envelope, version = written.etag)
    }

    // RFC 9110 ETags are quoted (optionally weak-prefixed); Drive change
    // tokens like headRevisionId are not and must not be sent as If-Match.
    private fun isHttpEtag(value: String): Boolean =
        value.startsWith("\"") || value.startsWith("W/")

    private fun assertWriteHeadFresh(currentVersion: String, head: DriveV2WriteHead) {
        if (isHttpEtag(currentVersion)) {
            if (head.etag != currentVersion) {
                throw SyncKitError(
                    SyncKitErrorCode.CONFLICT,
                    "The Drive dataset changed after it was last read.",
                )
            }
            return
        }
        if (head.headRevisionId != null && head.headRevisionId != currentVersion) {
            throw SyncKitError(
                SyncKitErrorCode.CONFLICT,
                "The Drive dataset changed after it was last read.",
            )
        }
    }

    override suspend fun grantExchangeAccess(
        emailAddress: String,
        sendNotificationEmail: Boolean?,
        emailMessage: String?,
    ): ExchangeAccessResult {
        requireNonEmpty(emailAddress, "emailAddress")
        val authorization = authorize()
        val storage = ensureStorage()
        val appPermissionId = drive.share(
            fileId = storage.appFolderId,
            emailAddress = emailAddress,
            role = "reader",
            authorization = authorization,
            sendNotificationEmail = sendNotificationEmail ?: true,
            emailMessage = emailMessage,
        )
        val exchangePermissionId = drive.share(
            fileId = storage.exchangesFolderId,
            emailAddress = emailAddress,
            role = "writer",
            authorization = authorization,
            sendNotificationEmail = false,
        )
        if (exchangePermissionId != appPermissionId) {
            throw SyncKitError(
                SyncKitErrorCode.NETWORK,
                "Google Drive returned inconsistent permission IDs for one account.",
            )
        }
        return ExchangeAccessResult(
            drivePermissionId = appPermissionId,
            appFolderId = storage.appFolderId,
        )
    }

    override suspend fun createInvitation(invitation: SharingInvitationV1): String {
        if (invitation.appId != appId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The invitation belongs to another application.",
            )
        }
        val storage = ensureStorage()
        if (invitation.appFolderId != storage.appFolderId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The invitation references another app folder.",
            )
        }
        return drive.create(
            name = "${invitation.exchangeId}-invitation.json",
            content = SyncKitJson.instance.encodeToString(
                SharingInvitationV1.serializer(),
                invitation,
            ),
            authorization = authorize(),
            parentId = storage.exchangesFolderId,
            contentType = "application/json",
            appProperties = properties("invitation") + mapOf(EXCHANGE_ID_PROPERTY to invitation.exchangeId),
        )
    }

    override suspend fun createKeyResponse(response: SharingPublicKeyResponseV1): String {
        if (response.appId != appId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The key response belongs to another application.",
            )
        }
        val storage = ensureStorage()
        return drive.create(
            name = "${response.exchangeId}-${response.keyId}-response.json",
            content = SyncKitJson.instance.encodeToString(
                SharingPublicKeyResponseV1.serializer(),
                response,
            ),
            authorization = authorize(),
            parentId = storage.exchangesFolderId,
            contentType = "application/json",
            appProperties = properties("key-response") + mapOf(
                EXCHANGE_ID_PROPERTY to response.exchangeId,
                KEY_ID_PROPERTY to response.keyId,
            ),
        )
    }

    override suspend fun listExchanges(
        exchangeId: String?,
        kind: String?,
    ): List<SharedExchangeFile> {
        val authorization = authorize()
        val storage = ensureStorage()
        val appProperties = buildMap {
            put(SYNC_KIT_APP_ID_PROPERTY, appId)
            put(SYNC_KIT_PROTOCOL_PROPERTY, SHARING_PROTOCOL)
            kind?.let { put(SYNC_KIT_KIND_PROPERTY, it) }
            exchangeId?.let { put(EXCHANGE_ID_PROPERTY, it) }
        }
        val files = listAll(authorization, storage.exchangesFolderId, appProperties)
        return files.map { file ->
            val fileKind = requiredProperty(file, SYNC_KIT_KIND_PROPERTY, "exchange")
            if (fileKind != "invitation" && fileKind != "key-response") {
                throw SyncKitError(
                    SyncKitErrorCode.COMPATIBILITY,
                    "A managed exchange file has an unsupported kind.",
                )
            }
            SharedExchangeFile(
                fileId = file.fileId,
                exchangeId = requiredProperty(file, EXCHANGE_ID_PROPERTY, "exchange"),
                kind = fileKind,
                keyId = file.appProperties?.get(KEY_ID_PROPERTY),
                createdTime = file.createdTime,
            )
        }
    }

    override suspend fun readInvitation(fileId: String): SharingInvitationV1 {
        val authorization = authorize()
        val metadata = drive.get(fileId, authorization)
        assertManagedFile(metadata, "invitation")
        return SharingCrypto.parseSharingInvitationV1(
            drive.readText(fileId, authorization),
        )
    }

    override suspend fun readKeyResponse(
        fileId: String,
        expectedDrivePermissionId: String,
    ): SharedKeyResponseFile {
        val authorization = authorize()
        val metadata = drive.get(fileId, authorization)
        assertManagedFile(metadata, "key-response")
        assertDriveFileProvenance(
            metadata,
            DriveFileProvenanceExpectation(permissionId = expectedDrivePermissionId),
        )
        val response = SharingCrypto.parseSharingPublicKeyResponseV1(
            drive.readText(fileId, authorization),
        )
        return SharedKeyResponseFile(
            fileId = fileId,
            response = response,
            ownerPermissionId = expectedDrivePermissionId,
        )
    }

    override suspend fun deleteDataset(fileId: String) {
        drive.delete(fileId, authorize())
    }

    override suspend fun trashDataset(fileId: String) {
        drive.trash(fileId, authorize())
    }

    override suspend fun deleteExchange(fileId: String) {
        drive.delete(fileId, authorize())
    }

    override suspend fun setDatasetPermission(
        fileId: String,
        emailAddress: String,
        role: SharingRole,
        existingDirectPermissionId: String?,
        hasInheritedReadAccess: Boolean,
    ): SharedDatasetPermission {
        val driveRole = if (role == SharingRole.VIEWER) "reader" else "writer"
        if (existingDirectPermissionId != null) {
            drive.updatePermission(fileId, existingDirectPermissionId, driveRole, authorize())
            return SharedDatasetPermission(
                permissionId = existingDirectPermissionId,
                role = driveRole,
            )
        }
        if (driveRole == "reader" && hasInheritedReadAccess) {
            return SharedDatasetPermission(role = driveRole)
        }
        val permissionId = drive.share(
            fileId = fileId,
            emailAddress = emailAddress,
            role = driveRole,
            authorization = authorize(),
            sendNotificationEmail = false,
        )
        return SharedDatasetPermission(permissionId = permissionId, role = driveRole)
    }

    override suspend fun removeDatasetPermission(fileId: String, permissionId: String) {
        drive.removePermission(fileId, permissionId, authorize())
    }

    override suspend fun listDatasetPermissions(fileId: String): List<SharedDatasetDrivePermission> =
        drive.listPermissions(fileId, authorize())
            .filter { it.type == "user" && (it.role == "reader" || it.role == "writer") }
            .map { permission ->
                SharedDatasetDrivePermission(
                    permissionId = permission.permissionId,
                    role = permission.role,
                    emailAddress = permission.emailAddress,
                    inherited = permission.inherited,
                )
            }

    override suspend fun listDatasetHeads(): List<SharedDatasetHead> {
        val authorization = authorize()
        val storage = ensureStorage()
        val files = listAll(authorization, storage.appFolderId, properties("dataset"))
        return files.map { file ->
            SharedDatasetHead(
                datasetId = requiredProperty(file, SYNC_KIT_DATASET_ID_PROPERTY, "dataset"),
                fileId = file.fileId,
                modifiedTime = file.modifiedTime,
                version = file.version,
                headRevisionId = file.headRevisionId,
                etag = file.etag,
            )
        }
    }

    private suspend fun ensureStorageNow(): SharedBackupStorage {
        val authorization = authorize()
        val appFolderId = selectedAppFolderId ?: ensureSyncKitFolder(
            EnsureSyncKitFolderOptions(
                appId = appId,
                authorization = authorization,
                folderName = folderName,
                parentFolderId = parentFolderId,
                drive = drive,
            ),
        ).appFolderId
        val exchangeProperties = properties("exchange-folder")
        val existing = drive.list(
            authorization = authorization,
            parentId = appFolderId,
            appProperties = exchangeProperties,
        )
        val exchangesFolderId = existing.files.find { it.name == "exchanges" }?.fileId
            ?: drive.createFolder(
                name = "exchanges",
                authorization = authorization,
                parentId = appFolderId,
                appProperties = exchangeProperties,
                writersCanShare = false,
            )
        return SharedBackupStorage(appFolderId, exchangesFolderId)
    }

    private suspend fun listAll(
        authorization: Authorization,
        parentId: String,
        appProperties: Map<String, String>,
    ): List<DriveFileMetadata> {
        val files = mutableListOf<DriveFileMetadata>()
        var pageToken: String? = null
        do {
            val page = drive.list(
                authorization = authorization,
                parentId = parentId,
                appProperties = appProperties,
                pageToken = pageToken,
            )
            files += page.files
            pageToken = page.nextPageToken
        } while (pageToken != null)
        return files
    }

    private fun properties(kind: String): Map<String, String> = mapOf(
        SYNC_KIT_APP_ID_PROPERTY to appId,
        SYNC_KIT_PROTOCOL_PROPERTY to SHARING_PROTOCOL,
        SYNC_KIT_KIND_PROPERTY to kind,
    )

    private fun assertManagedFile(file: DriveFileMetadata, kind: String) {
        if (
            file.appProperties?.get(SYNC_KIT_APP_ID_PROPERTY) != appId ||
            file.appProperties?.get(SYNC_KIT_PROTOCOL_PROPERTY) != SHARING_PROTOCOL ||
            file.appProperties?.get(SYNC_KIT_KIND_PROPERTY) != kind
        ) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The selected Drive file is not a managed $kind for this application.",
            )
        }
    }

    private fun assertEnvelopeDataset(datasetId: String, envelope: SharedBackupEnvelopeV1) {
        if (envelope.appId != appId || envelope.backupId != datasetId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The shared-backup envelope belongs to another dataset.",
            )
        }
    }

    private suspend fun authorize(): Authorization = authorizationProvider.authorize()

    private fun requiredProperty(
        file: DriveFileMetadata,
        name: String,
        label: String,
    ): String = file.appProperties?.get(name)
        ?: throw SyncKitError(
            SyncKitErrorCode.COMPATIBILITY,
            "A managed $label file is missing $name.",
        )

    private fun requireNonEmpty(value: String, name: String) {
        if (value.isBlank()) throw IllegalArgumentException("$name must not be empty.")
    }

    private companion object {
        private var driveV2FallbackLogged = false

        private fun logDriveV2FallbackOnce() {
            if (driveV2FallbackLogged) return
            driveV2FallbackLogged = true
            try {
                Log.w(
                    "GoogleDriveSharedBackupTransport",
                    "Google Drive v2 conditional writes are unavailable; falling back to preflight-only writes.",
                )
            } catch (_: RuntimeException) {
                // android.util.Log is not mocked in JVM unit tests.
            }
        }
    }
}
