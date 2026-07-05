package com.keyneom.synckit.sharing

import com.keyneom.synckit.sharing.checkpoint.SharedDatasetHead
import com.keyneom.synckit.sharing.checkpoint.SharingChangeDetectionResult
import com.keyneom.synckit.sharing.checkpoint.SharingNotificationEventKind
import com.keyneom.synckit.sharing.checkpoint.SharingSyncCheckpoint
import java.util.Date

private fun datasetHeadSignature(head: SharedDatasetHead): String =
    listOf(
        head.etag.orEmpty(),
        head.version.orEmpty(),
        head.headRevisionId.orEmpty(),
        head.modifiedTime.orEmpty(),
    ).joinToString("|")

data class SharingChangeDetectorOptions(
    val now: () -> Date = { Date() },
    val tokenExpiresAt: Long? = null,
    val tokenExpiringSoonMs: Long = 5 * 60_000,
)

suspend fun detectSharingChanges(
    listKeyResponses: suspend () -> List<KeyResponseRef>,
    listDatasetHeads: suspend () -> List<SharedDatasetHead>,
    checkpoint: SharingSyncCheckpoint,
    options: SharingChangeDetectorOptions = SharingChangeDetectorOptions(),
): SharingChangeDetectionResult {
    val now = options.now()
    val events = mutableListOf<SharingNotificationEventKind>()
    if (options.tokenExpiresAt != null) {
        if (options.tokenExpiresAt <= now.time) {
            events += SharingNotificationEventKind.TokenExpired
            return SharingChangeDetectionResult(
                checkpoint = checkpoint.copy(lastPollAt = now.toInstant().toString()),
                events = events,
            )
        }
        if (options.tokenExpiresAt - now.time <= options.tokenExpiringSoonMs) {
            events += SharingNotificationEventKind.TokenExpiringSoon(
                expiresAt = Date(options.tokenExpiresAt).toInstant().toString(),
            )
        }
    }
    val seenResponses = (checkpoint.lastSeenKeyResponseFileIds ?: emptyList()).toSet()
    val responses = listKeyResponses()
    for (response in responses) {
        if (response.fileId !in seenResponses) {
            events += SharingNotificationEventKind.PendingKeyResponse(
                exchangeId = response.exchangeId,
                fileId = response.fileId,
            )
        }
    }
    val previousHeads = checkpoint.datasetHeads.orEmpty()
    val nextHeads = linkedMapOf<String, SharedDatasetHead>()
    val heads = listDatasetHeads()
    for (head in heads) {
        nextHeads[head.datasetId] = head
        val previous = previousHeads[head.datasetId]
        if (previous != null && datasetHeadSignature(previous) != datasetHeadSignature(head)) {
            events += SharingNotificationEventKind.SharedDatasetChanged(
                datasetId = head.datasetId,
                fileId = head.fileId,
            )
        }
    }
    return SharingChangeDetectionResult(
        checkpoint = SharingSyncCheckpoint(
            lastPollAt = now.toInstant().toString(),
            lastSeenKeyResponseFileIds = responses.map { it.fileId },
            datasetHeads = nextHeads,
        ),
        events = events,
    )
}

data class KeyResponseRef(
    val fileId: String,
    val exchangeId: String,
)

class SharingChangeDetector(
    private val listKeyResponses: suspend () -> List<KeyResponseRef>,
    private val listDatasetHeads: suspend () -> List<SharedDatasetHead>,
    private val tokenExpiresAt: (() -> Long?)? = null,
    private val now: () -> Date = { Date() },
    private val tokenExpiringSoonMs: Long = 5 * 60_000,
) {
    suspend fun detect(checkpoint: SharingSyncCheckpoint): SharingChangeDetectionResult =
        detectSharingChanges(
            listKeyResponses = listKeyResponses,
            listDatasetHeads = listDatasetHeads,
            checkpoint = checkpoint,
            options = SharingChangeDetectorOptions(
                now = now,
                tokenExpiresAt = tokenExpiresAt?.invoke(),
                tokenExpiringSoonMs = tokenExpiringSoonMs,
            ),
        )
}

fun createSharingChangeDetectorFromTransport(
    transport: SharedBackupTransport,
    tokenExpiresAt: (() -> Long?)? = null,
    now: () -> Date = { Date() },
    tokenExpiringSoonMs: Long = 5 * 60_000,
): SharingChangeDetector = SharingChangeDetector(
    listKeyResponses = {
        transport.listExchanges(kind = "key-response").map { exchange ->
            KeyResponseRef(fileId = exchange.fileId, exchangeId = exchange.exchangeId)
        }
    },
    listDatasetHeads = { transport.listDatasetHeads() },
    tokenExpiresAt = tokenExpiresAt,
    now = now,
    tokenExpiringSoonMs = tokenExpiringSoonMs,
)
