package com.keyneom.synckit.sharing.checkpoint

import kotlinx.serialization.Serializable

@Serializable
data class SharedDatasetHead(
    val datasetId: String,
    val fileId: String,
    val modifiedTime: String? = null,
    val version: String? = null,
    val headRevisionId: String? = null,
    val etag: String? = null,
)

@Serializable
data class SharingSyncCheckpoint(
    val lastPollAt: String? = null,
    val lastSeenKeyResponseFileIds: List<String>? = null,
    val datasetHeads: Map<String, SharedDatasetHead>? = null,
)

@Serializable
sealed class SharingNotificationEvent {
    @Serializable
    data class PendingKeyResponse(
        val exchangeId: String,
        val fileId: String,
    ) : SharingNotificationEvent()

    @Serializable
    data class SharedDatasetChanged(
        val datasetId: String,
        val fileId: String,
    ) : SharingNotificationEvent()

    @Serializable
    data class TokenExpiringSoon(
        val expiresAt: String,
    ) : SharingNotificationEvent()

    @Serializable
    data object TokenExpired : SharingNotificationEvent()
}

data class SharingChangeDetectionResult(
    val checkpoint: SharingSyncCheckpoint,
    val events: List<SharingNotificationEventKind>,
)

sealed class SharingNotificationEventKind {
    data class PendingKeyResponse(
        val exchangeId: String,
        val fileId: String,
    ) : SharingNotificationEventKind()

    data class SharedDatasetChanged(
        val datasetId: String,
        val fileId: String,
    ) : SharingNotificationEventKind()

    data class TokenExpiringSoon(
        val expiresAt: String,
    ) : SharingNotificationEventKind()

    data object TokenExpired : SharingNotificationEventKind()
}
