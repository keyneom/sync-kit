package com.keyneom.synckit.stores

const val SYNC_KIT_APP_ID_PROPERTY = "sync-kit-app-id"
const val SYNC_KIT_KIND_PROPERTY = "sync-kit-kind"
const val SYNC_KIT_DATASET_ID_PROPERTY = "sync-kit-dataset-id"
const val SYNC_KIT_PROTOCOL_PROPERTY = "sync-kit-protocol"
const val DRIVE_FOLDER_MIME_TYPE = "application/vnd.google-apps.folder"

fun defaultSyncKitAppFolderName(appId: String): String = "Sync Kit - $appId"

fun escapeDriveQuery(value: String): String =
    value.replace("\\", "\\\\").replace("'", "\\'")
