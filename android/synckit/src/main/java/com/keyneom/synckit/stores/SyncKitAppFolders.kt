package com.keyneom.synckit.stores

import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

data class SyncKitAppFolder(
    val appFolderId: String,
    val name: String,
    val modifiedTime: String? = null,
)

data class ListAccessibleSyncKitAppFoldersOptions(
    val appId: String,
    val authorization: Authorization,
    val drive: GoogleDriveFileStore = GoogleDriveFileStore(),
)

suspend fun listAccessibleSyncKitAppFolders(
    options: ListAccessibleSyncKitAppFoldersOptions,
): List<SyncKitAppFolder> = withContext(Dispatchers.IO) {
    require(options.appId.isNotBlank()) { "appId must not be empty." }
    val folders = mutableListOf<SyncKitAppFolder>()
    var pageToken: String? = null
    do {
        val page = options.drive.list(
            options.authorization,
            appProperties = mapOf(
                SYNC_KIT_APP_ID_PROPERTY to options.appId,
                SYNC_KIT_KIND_PROPERTY to "app-root",
            ),
            pageToken = pageToken,
        )
        for (file in page.files) {
            if (file.mimeType == DRIVE_FOLDER_MIME_TYPE) {
                folders += SyncKitAppFolder(
                    appFolderId = file.fileId,
                    name = file.name,
                    modifiedTime = file.modifiedTime,
                )
            }
        }
        pageToken = page.nextPageToken
    } while (pageToken != null)
    folders.sortedBy { it.name }
}

data class GoogleDriveSyncKitFolder(
    val appFolderId: String,
)

data class EnsureSyncKitFolderOptions(
    val appId: String,
    val authorization: Authorization,
    val folderName: String? = null,
    val parentFolderId: String? = null,
    val drive: GoogleDriveFileStore = GoogleDriveFileStore(),
    val writersCanShare: Boolean = false,
)

suspend fun ensureSyncKitFolder(options: EnsureSyncKitFolderOptions): GoogleDriveSyncKitFolder =
    withContext(Dispatchers.IO) {
        require(options.appId.isNotBlank()) { "appId must not be empty." }
        val folderName = options.folderName ?: defaultSyncKitAppFolderName(options.appId)
        val appProperties = mapOf(
            SYNC_KIT_KIND_PROPERTY to "app-root",
            SYNC_KIT_APP_ID_PROPERTY to options.appId,
        )
        val existing = findFolder(
            options.drive,
            options.authorization,
            folderName,
            options.parentFolderId,
            appProperties,
        )
        val appFolderId = existing ?: options.drive.createFolder(
            folderName,
            options.authorization,
            parentId = options.parentFolderId,
            appProperties = appProperties,
            writersCanShare = options.writersCanShare,
        )
        GoogleDriveSyncKitFolder(appFolderId)
    }

private suspend fun findFolder(
    drive: GoogleDriveFileStore,
    authorization: Authorization,
    name: String,
    parentId: String?,
    appProperties: Map<String, String>,
): String? {
    val listed = drive.list(
        authorization,
        parentId = parentId,
        appProperties = appProperties,
    )
    return listed.files.find { it.name == name && it.mimeType == DRIVE_FOLDER_MIME_TYPE }?.fileId
}
