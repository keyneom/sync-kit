package com.keyneom.synckit.snapshot

import android.app.Activity
import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.core.AuthorizationProvider
import com.keyneom.synckit.core.CloudStore
import com.keyneom.synckit.core.CreatedKey
import com.keyneom.synckit.core.KeyProvider
import com.keyneom.synckit.core.StoredEnvelope
import com.keyneom.synckit.core.SyncCodec
import com.keyneom.synckit.core.SyncOutcome
import com.keyneom.synckit.core.SyncReason
import com.keyneom.synckit.crypto.PasskeyProfile
import com.keyneom.synckit.crypto.SyncEnvelopeV1
import com.keyneom.synckit.crypto.V1CompatibilityProfile
import com.keyneom.synckit.crypto.V1Compression
import com.keyneom.synckit.crypto.V1EnvelopeCrypto
import com.keyneom.synckit.crypto.V1KeyMetadata
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class SnapshotSyncControllerTest {
    private val profile = V1CompatibilityProfile(
        appId = "demo",
        filename = "demo-sync-v1.json",
        aad = "demo-aad",
        hkdfInfo = "demo-hkdf",
        compression = V1Compression.NONE,
        passkey = PasskeyProfile("Demo", "sync", "Demo sync"),
    )

    private val codec = object : SyncCodec<String> {
        override fun serialize(value: String): ByteArray = value.toByteArray()
        override fun parse(bytes: ByteArray): String = bytes.toString(Charsets.UTF_8)
        override fun merge(local: String, remote: String): String =
            if (local >= remote) local else remote
        override fun fingerprint(value: String): String = value
        override fun updatedAt(value: String): String = "2026-07-04T00:00:00.000Z"
    }

    private val crypto = V1EnvelopeCrypto(profile, codec)
    private val activity = Activity()
    private lateinit var store: FakeCloudStore
    private lateinit var keys: FakeKeyProvider
    private lateinit var controller: SnapshotSyncController<String>

    private val secret = ByteArray(32) { 1 }
    private val salt = ByteArray(32) { 2 }
    private val prfInput = ByteArray(32) { 3 }
    private lateinit var contentKey: ByteArray
    private lateinit var remoteEnvelope: SyncEnvelopeV1

    @Before
    fun setUp() {
        contentKey = crypto.deriveContentKey(secret, salt)
        val metadata = V1KeyMetadata("credential", "example.com", prfInput, salt)
        remoteEnvelope = crypto.encrypt("remote", contentKey, metadata)
        store = FakeCloudStore(StoredEnvelope("file", remoteEnvelope))
        keys = FakeKeyProvider(metadata, contentKey)
        controller = SnapshotSyncController(
            SnapshotSyncOptions(
                appId = profile.appId,
                codec = codec,
                envelopeCrypto = crypto,
                keyProvider = keys,
                authorizationProvider = FixedAuth(),
                cloudStore = store,
                readLocal = { "local" },
                applyMerged = { applied = it },
                activity = { activity },
            ),
        )
    }

    private var applied: String? = null

    @Test
    fun syncSkipsUploadWhenMergedMatchesRemote() = runBlocking {
        val result = controller.sync(SyncReason.MANUAL)
        assertEquals(SyncOutcome.UNCHANGED, result.outcome)
        assertEquals("remote", applied)
        assertEquals(0, store.writeCalls)
    }

    @Test
    fun syncUploadsWhenLocalChanges() = runBlocking {
        controller = SnapshotSyncController(
            SnapshotSyncOptions(
                appId = profile.appId,
                codec = codec,
                envelopeCrypto = crypto,
                keyProvider = keys,
                authorizationProvider = FixedAuth(),
                cloudStore = store,
                readLocal = { "zebra" },
                applyMerged = { applied = it },
                activity = { activity },
            ),
        )
        val result = controller.sync(SyncReason.CHANGE)
        assertEquals(SyncOutcome.MERGED, result.outcome)
        assertEquals("zebra", applied)
        assertEquals(1, store.writeCalls)
    }

    @Test
    fun setupRefusesWhenSnapshotExists() = runBlocking {
        try {
            controller.setup()
            org.junit.Assert.fail("expected existing snapshot error")
        } catch (error: Exception) {
            assertTrue(error.message!!.contains("already exists"))
        }
    }

    @Test
    fun deleteClearsKeys() = runBlocking {
        controller.delete()
        assertEquals("file", store.deletedFileId)
        assertTrue(keys.cleared)
    }

    private class FixedAuth : AuthorizationProvider {
        override suspend fun authorize(): Authorization = Authorization("token")
    }

    private class FakeCloudStore(initial: StoredEnvelope?) : CloudStore {
        var snapshot = initial
        var writeCalls = 0
        var deletedFileId: String? = null

        override suspend fun find(appId: String, authorization: Authorization): StoredEnvelope? =
            snapshot

        override suspend fun write(
            appId: String,
            envelope: SyncEnvelopeV1,
            authorization: Authorization,
            existingId: String?,
        ): String {
            writeCalls += 1
            val id = existingId ?: "new"
            snapshot = StoredEnvelope(id, envelope)
            return id
        }

        override suspend fun delete(appId: String, fileId: String, authorization: Authorization) {
            deletedFileId = fileId
            snapshot = null
        }
    }

    private class FakeKeyProvider(
        private val metadata: V1KeyMetadata,
        private val key: ByteArray,
    ) : KeyProvider {
        var cleared = false

        override suspend fun create(activity: Activity, appId: String): CreatedKey =
            CreatedKey(metadata, key.copyOf())

        override suspend fun unlock(activity: Activity, envelope: SyncEnvelopeV1): ByteArray =
            key.copyOf()

        override fun clear() {
            cleared = true
        }
    }
}
