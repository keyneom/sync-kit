package com.keyneom.synckit.core

import android.app.Activity
import com.keyneom.synckit.crypto.SyncEnvelopeV1
import com.keyneom.synckit.crypto.V1KeyMetadata

enum class SyncReason {
    STARTUP,
    FOREGROUND,
    CHANGE,
    MANUAL,
}

enum class SnapshotOperation {
    SETUP,
    ENABLE,
    SYNC,
    RESET,
}

enum class SyncOutcome {
    CREATED,
    MERGED,
    UNCHANGED,
    RESET,
    COALESCED,
}

data class Authorization(
    val accessToken: String,
    val expiresAt: Long? = null,
)

data class StoredEnvelope(
    val fileId: String,
    val envelope: SyncEnvelopeV1,
)

data class CreatedKey(
    val metadata: V1KeyMetadata,
    val key: ByteArray,
)

data class SyncResult<T>(
    val operation: SnapshotOperation,
    val outcome: SyncOutcome,
    val fileId: String?,
    val syncedAt: String?,
    val value: T?,
)

interface AuthorizationProvider {
    suspend fun authorize(): Authorization
    fun clear() {}
}

interface CloudStore {
    suspend fun find(appId: String, authorization: Authorization): StoredEnvelope?
    suspend fun write(
        appId: String,
        envelope: SyncEnvelopeV1,
        authorization: Authorization,
        existingId: String? = null,
    ): String
    suspend fun delete(appId: String, fileId: String, authorization: Authorization)
}

interface KeyProvider {
    /**
     * Establishes a new key. The returned key is the **derived content key**,
     * ready for encryption — see [unlock].
     */
    suspend fun create(activity: Activity, appId: String): CreatedKey

    /**
     * Returns the **derived content key**, not the raw secret it came from.
     *
     * Passkey-backed providers run the Credential Manager PRF ceremony and then
     * the envelope's KDF over its `kdfSalt` before returning. Use the result
     * directly; **do not derive from it again.** Deriving a second time yields
     * `KDF(KDF(secret, salt), salt)`, which differs from what every other
     * platform holds, so the envelope fails to open in a way that looks like
     * Credential Manager returned the wrong credential rather than a
     * key-derivation mismatch.
     */
    suspend fun unlock(activity: Activity, envelope: SyncEnvelopeV1): ByteArray

    fun clear()
}

interface SyncCodec<T> {
    fun serialize(value: T): ByteArray
    fun parse(bytes: ByteArray): T
    fun merge(local: T, remote: T): T
    fun fingerprint(value: T): String
    fun updatedAt(value: T): String
}
