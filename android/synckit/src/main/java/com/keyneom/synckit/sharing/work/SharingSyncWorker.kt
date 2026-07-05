package com.keyneom.synckit.sharing.work

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.WorkerParameters
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.sharing.SharedBackupTransport
import com.keyneom.synckit.sharing.checkpoint.SharingSyncCheckpoint
import com.keyneom.synckit.sharing.createSharingChangeDetectorFromTransport
import kotlinx.serialization.encodeToString

/**
 * WorkManager skeleton for Tier A sharing change detection.
 * Consumers supply transport/auth wiring and handle notification UX.
 */
abstract class SharingSyncWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    abstract suspend fun transport(): SharedBackupTransport

    abstract suspend fun loadCheckpoint(): SharingSyncCheckpoint

    abstract suspend fun saveCheckpoint(checkpoint: SharingSyncCheckpoint)

    open fun tokenExpiresAt(): Long? =
        inputData.getLong(KEY_TOKEN_EXPIRES_AT, Long.MIN_VALUE).takeIf { it != Long.MIN_VALUE }

    override suspend fun doWork(): Result {
        val detector = createSharingChangeDetectorFromTransport(
            transport = transport(),
            tokenExpiresAt = { tokenExpiresAt() },
        )
        val detection = detector.detect(loadCheckpoint())
        saveCheckpoint(detection.checkpoint)
        val output = Data.Builder()
            .putString(KEY_EVENTS_JSON, encodeEvents(detection.events))
            .putString(
                KEY_CHECKPOINT_JSON,
                SyncKitJson.instance.encodeToString(
                    SharingSyncCheckpoint.serializer(),
                    detection.checkpoint,
                ),
            )
            .build()
        return Result.success(output)
    }

    companion object {
        const val KEY_TOKEN_EXPIRES_AT = "tokenExpiresAt"
        const val KEY_EVENTS_JSON = "eventsJson"
        const val KEY_CHECKPOINT_JSON = "checkpointJson"

        fun encodeEvents(events: List<com.keyneom.synckit.sharing.checkpoint.SharingNotificationEventKind>): String =
            SyncKitJson.instance.encodeToString(
                kotlinx.serialization.builtins.ListSerializer(EventKindSurrogate.serializer()),
                events.map { it.toSurrogate() },
            )
    }
}

@kotlinx.serialization.Serializable
private data class EventKindSurrogate(
    val kind: String,
    val exchangeId: String? = null,
    val fileId: String? = null,
    val datasetId: String? = null,
    val expiresAt: String? = null,
)

private fun com.keyneom.synckit.sharing.checkpoint.SharingNotificationEventKind.toSurrogate(): EventKindSurrogate =
    when (this) {
        is com.keyneom.synckit.sharing.checkpoint.SharingNotificationEventKind.PendingKeyResponse ->
            EventKindSurrogate("pending-key-response", exchangeId = exchangeId, fileId = fileId)
        is com.keyneom.synckit.sharing.checkpoint.SharingNotificationEventKind.SharedDatasetChanged ->
            EventKindSurrogate("shared-dataset-changed", datasetId = datasetId, fileId = fileId)
        is com.keyneom.synckit.sharing.checkpoint.SharingNotificationEventKind.TokenExpiringSoon ->
            EventKindSurrogate("token-expiring-soon", expiresAt = expiresAt)
        com.keyneom.synckit.sharing.checkpoint.SharingNotificationEventKind.TokenExpired ->
            EventKindSurrogate("token-expired")
    }
