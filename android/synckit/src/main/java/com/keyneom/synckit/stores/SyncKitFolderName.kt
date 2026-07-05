package com.keyneom.synckit.stores

private const val DRIVE_FOLDER_NAME_MAX_LENGTH = 200
private val INVALID_DRIVE_FOLDER_CHARS = Regex("[\\u0000-\\u001f\\\\/]")

data class SyncKitFolderNameInput(
    val appDisplayName: String,
    val profileLabel: String,
    val ownerLabel: String? = null,
)

fun sanitizeDriveFolderName(name: String): String {
    val collapsed = name
        .replace(INVALID_DRIVE_FOLDER_CHARS, " ")
        .replace(Regex("\\s+"), " ")
        .trim()
    require(collapsed.isNotEmpty()) { "The Drive folder name must not be empty." }
    if (collapsed.length <= DRIVE_FOLDER_NAME_MAX_LENGTH) return collapsed
    return collapsed.take(DRIVE_FOLDER_NAME_MAX_LENGTH).trimEnd()
}

fun buildSyncKitFolderName(input: SyncKitFolderNameInput): String {
    require(input.appDisplayName.isNotBlank()) { "appDisplayName must not be empty." }
    require(input.profileLabel.isNotBlank()) { "profileLabel must not be empty." }
    val base = "${input.appDisplayName.trim()} — ${input.profileLabel.trim()}"
    val withOwner = input.ownerLabel?.trim()?.takeIf { it.isNotEmpty() }?.let { owner ->
        "$base ($owner)"
    } ?: base
    return sanitizeDriveFolderName(withOwner)
}
