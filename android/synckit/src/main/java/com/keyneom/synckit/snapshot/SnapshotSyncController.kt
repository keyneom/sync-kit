package com.keyneom.synckit.snapshot

import android.app.Activity
import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.core.AuthorizationProvider
import com.keyneom.synckit.core.CloudStore
import com.keyneom.synckit.core.KeyProvider
import com.keyneom.synckit.core.SnapshotOperation
import com.keyneom.synckit.core.StoredEnvelope
import com.keyneom.synckit.core.SyncCodec
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.core.SyncOutcome
import com.keyneom.synckit.core.SyncReason
import com.keyneom.synckit.core.SyncResult
import com.keyneom.synckit.crypto.V1EnvelopeCrypto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicInteger

data class SnapshotSyncOptions<T>(
    val appId: String,
    val codec: SyncCodec<T>,
    val envelopeCrypto: V1EnvelopeCrypto<T>,
    val keyProvider: KeyProvider,
    val authorizationProvider: AuthorizationProvider,
    val cloudStore: CloudStore,
    val readLocal: suspend () -> T,
    val applyMerged: suspend (T) -> Unit,
    val activity: () -> Activity,
)

/**
 * Serialized snapshot orchestration matching the npm `/snapshot` controller.
 * Queues at most one change-sync while another operation is in flight.
 */
class SnapshotSyncController<T>(
    private val options: SnapshotSyncOptions<T>,
) {
    private val mutex = Mutex()
    private val operationCount = AtomicInteger(0)
    private val queuedChangeLock = Any()
    @Volatile
    private var queuedChange: CompletableDeferred<SyncResult<T>>? = null

    fun operationInProgress(): Boolean = operationCount.get() > 0

    suspend fun setup(): SyncResult<T> = runExclusive { setupNow() }

    suspend fun enable(): SyncResult<T> = runExclusive { mergeNow(SnapshotOperation.ENABLE) }

    suspend fun sync(reason: SyncReason): SyncResult<T> {
        if (operationCount.get() > 0) {
            if (reason != SyncReason.CHANGE) {
                return coalescedResult()
            }
            val (deferred, isLeader) = synchronized(queuedChangeLock) {
                val existing = queuedChange
                if (existing != null) {
                    return@synchronized Pair(existing, false)
                }
                val created = CompletableDeferred<SyncResult<T>>()
                queuedChange = created
                Pair(created, true)
            }
            if (!isLeader) {
                return deferred.await()
            }
            try {
                val result = runExclusive {
                    synchronized(queuedChangeLock) {
                        if (queuedChange === deferred) queuedChange = null
                    }
                    mergeNow(SnapshotOperation.SYNC)
                }
                deferred.complete(result)
                return result
            } catch (error: Throwable) {
                deferred.completeExceptionally(error)
                throw error
            }
        }
        return runExclusive { mergeNow(SnapshotOperation.SYNC) }
    }

    suspend fun reset(): SyncResult<T> = runExclusive { resetNow() }

    suspend fun delete() = runExclusive {
        val authorization = options.authorizationProvider.authorize()
        val existing = options.cloudStore.find(options.appId, authorization)
        if (existing != null) {
            options.cloudStore.delete(options.appId, existing.fileId, authorization)
        }
        lock()
    }

    fun lock() {
        options.keyProvider.clear()
        options.authorizationProvider.clear()
    }

    private suspend fun <R> runExclusive(operation: suspend () -> R): R {
        operationCount.incrementAndGet()
        return try {
            mutex.withLock { operation() }
        } finally {
            operationCount.decrementAndGet()
        }
    }

    private fun coalescedResult(): SyncResult<T> =
        SyncResult(
            operation = SnapshotOperation.SYNC,
            outcome = SyncOutcome.COALESCED,
            fileId = null,
            syncedAt = null,
            value = null,
        )

    private suspend fun setupNow(): SyncResult<T> {
        val authorization = options.authorizationProvider.authorize()
        if (options.cloudStore.find(options.appId, authorization) != null) {
            throw SyncKitError(
                SyncKitErrorCode.STATE,
                "A ${options.appId} encrypted snapshot already exists.",
            )
        }
        val local = options.readLocal()
        val created = options.keyProvider.create(options.activity(), options.appId)
        return try {
            val envelope = options.envelopeCrypto.encrypt(local, created.key, created.metadata)
            val fileId = options.cloudStore.write(options.appId, envelope, authorization)
            SyncResult(
                operation = SnapshotOperation.SETUP,
                outcome = SyncOutcome.CREATED,
                fileId = fileId,
                syncedAt = envelope.updatedAt,
                value = local,
            )
        } finally {
            created.key.fill(0)
        }
    }

    private suspend fun mergeNow(operation: SnapshotOperation): SyncResult<T> {
        val authorization = options.authorizationProvider.authorize()
        val existing = findRequired(authorization)
        val key = options.keyProvider.unlock(options.activity(), existing.envelope)
        return try {
            val remote = try {
                options.envelopeCrypto.decrypt(existing.envelope, key)
            } catch (error: Exception) {
                options.keyProvider.clear()
                throw error
            }
            val local = options.readLocal()
            val merged = options.codec.merge(local, remote)
            val cloudChanged =
                options.codec.fingerprint(merged) != options.codec.fingerprint(remote)
            var syncedAt = existing.envelope.updatedAt
            var fileId = existing.fileId
            if (cloudChanged) {
                val metadata = options.envelopeCrypto.metadataFromEnvelope(existing.envelope)
                val envelope = options.envelopeCrypto.encrypt(merged, key, metadata)
                fileId = options.cloudStore.write(
                    options.appId,
                    envelope,
                    authorization,
                    existing.fileId,
                )
                syncedAt = envelope.updatedAt
            }
            options.applyMerged(merged)
            SyncResult(
                operation = operation,
                outcome = if (cloudChanged) SyncOutcome.MERGED else SyncOutcome.UNCHANGED,
                fileId = fileId,
                syncedAt = syncedAt,
                value = merged,
            )
        } finally {
            key.fill(0)
        }
    }

    private suspend fun resetNow(): SyncResult<T> {
        val authorization = options.authorizationProvider.authorize()
        val existing = findRequired(authorization)
        options.keyProvider.clear()
        val local = options.readLocal()
        val created = options.keyProvider.create(options.activity(), options.appId)
        return try {
            val envelope = options.envelopeCrypto.encrypt(local, created.key, created.metadata)
            val fileId = options.cloudStore.write(
                options.appId,
                envelope,
                authorization,
                existing.fileId,
            )
            SyncResult(
                operation = SnapshotOperation.RESET,
                outcome = SyncOutcome.RESET,
                fileId = fileId,
                syncedAt = envelope.updatedAt,
                value = local,
            )
        } finally {
            created.key.fill(0)
        }
    }

    private suspend fun findRequired(authorization: Authorization): StoredEnvelope =
        options.cloudStore.find(options.appId, authorization)
            ?: throw SyncKitError(
                SyncKitErrorCode.NOT_FOUND,
                "No ${options.appId} encrypted snapshot was found.",
            )
}
