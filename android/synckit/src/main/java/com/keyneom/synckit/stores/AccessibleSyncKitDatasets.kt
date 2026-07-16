package com.keyneom.synckit.stores

import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.sharing.SHARING_PROTOCOL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class AccessibleSyncKitDataset(
    val datasetId: String,
    val fileId: String,
    val name: String,
    val appFolderId: String? = null,
    val canEdit: Boolean? = null,
    val modifiedTime: String? = null,
)

data class ListAccessibleSyncKitDatasetsOptions(
    val appId: String,
    val authorization: Authorization,
    val drive: GoogleDriveFileStore = GoogleDriveFileStore(),
)

/**
 * Lists every managed sharing dataset already visible to the current
 * `drive.file` grant, including files whose parent app-root is not listable.
 * Malformed managed files are skipped so one damaged file cannot hide the
 * healthy discovery set.
 */
suspend fun listAccessibleSyncKitDatasets(
    options: ListAccessibleSyncKitDatasetsOptions,
): List<AccessibleSyncKitDataset> = withContext(Dispatchers.IO) {
    require(options.appId.isNotBlank()) { "appId must not be empty." }
    val byFileId = linkedMapOf<String, AccessibleSyncKitDataset>()
    var pageToken: String? = null
    do {
        val page = options.drive.list(
            options.authorization,
            appProperties = sharingProperties(options.appId, "dataset"),
            pageToken = pageToken,
        )
        for (file in page.files) {
            if (file.fileId in byFileId || !isManagedDataset(file, options.appId)) continue
            val datasetId = file.appProperties?.get(SYNC_KIT_DATASET_ID_PROPERTY)
                ?.trim()
                ?.takeIf { it.isNotEmpty() }
                ?: continue
            byFileId[file.fileId] = AccessibleSyncKitDataset(
                datasetId = datasetId,
                fileId = file.fileId,
                name = file.name,
                appFolderId = file.parents?.firstOrNull()?.trim()?.takeIf { it.isNotEmpty() },
                canEdit = file.capabilities?.canEdit,
                modifiedTime = file.modifiedTime,
            )
        }
        pageToken = page.nextPageToken
    } while (pageToken != null)
    byFileId.values.sortedWith(
        compareBy<AccessibleSyncKitDataset>(
            { it.appFolderId.orEmpty() },
            { it.datasetId },
            { it.fileId },
        ),
    )
}

internal fun sharingProperties(appId: String, kind: String): Map<String, String> = mapOf(
    SYNC_KIT_APP_ID_PROPERTY to appId,
    SYNC_KIT_PROTOCOL_PROPERTY to SHARING_PROTOCOL,
    SYNC_KIT_KIND_PROPERTY to kind,
)

private fun isManagedDataset(file: DriveFileMetadata, appId: String): Boolean {
    val properties = file.appProperties ?: return false
    return properties[SYNC_KIT_APP_ID_PROPERTY] == appId &&
        properties[SYNC_KIT_PROTOCOL_PROPERTY] == SHARING_PROTOCOL &&
        properties[SYNC_KIT_KIND_PROPERTY] == "dataset"
}
