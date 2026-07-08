package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectedSharingIdentityStoreTest {
    private fun record(appId: String = "easy-bc"): ProtectedSharingIdentityV1 {
        val wrappingKey = ByteArray(32) { it.toByte() }
        val metadata = com.keyneom.synckit.crypto.V1KeyMetadata(
            credentialId = Base64Url.encode(ByteArray(12) { it.toByte() }),
            rpId = "keyneom.github.io",
            prfInput = ByteArray(32) { (it + 1).toByte() },
            kdfSalt = ByteArray(32) { (it + 2).toByte() },
        )
        return ProtectedSharingIdentityCrypto.create(appId, metadata, wrappingKey).record
    }

    private class FakeStore(
        var current: ProtectedSharingIdentityV1? = null,
        val failSave: Boolean = false,
    ) : ProtectedSharingIdentityStore {
        var saves = 0
        var deletes = 0
        override suspend fun load(appId: String) = current
        override suspend fun save(record: ProtectedSharingIdentityV1) {
            saves++
            if (failSave) throw RuntimeException("offline")
            current = record
        }
        override suspend fun delete(appId: String) {
            deletes++
            current = null
        }
    }

    @Test
    fun migratingReturnsPrimaryWithoutTouchingLegacy() = runBlocking {
        val primary = FakeStore(current = record())
        val legacy = FakeStore(current = record())
        val store = MigratingProtectedSharingIdentityStore(primary, legacy)
        assertEquals(primary.current!!.publicKey.keyId, store.load("easy-bc")!!.publicKey.keyId)
        assertEquals(0, primary.saves)
    }

    @Test
    fun migratingPromotesLegacyWhenPrimaryEmpty() = runBlocking {
        val legacyRecord = record()
        val primary = FakeStore()
        val legacy = FakeStore(current = legacyRecord)
        val store = MigratingProtectedSharingIdentityStore(primary, legacy)
        assertEquals(legacyRecord.publicKey.keyId, store.load("easy-bc")!!.publicKey.keyId)
        assertEquals(1, primary.saves)
        assertEquals(legacyRecord.publicKey.keyId, primary.current!!.publicKey.keyId)
    }

    @Test
    fun migratingStillReturnsLegacyWhenPromotionFails() = runBlocking {
        val legacyRecord = record()
        val primary = FakeStore(failSave = true)
        val legacy = FakeStore(current = legacyRecord)
        val store = MigratingProtectedSharingIdentityStore(primary, legacy)
        assertEquals(legacyRecord.publicKey.keyId, store.load("easy-bc")!!.publicKey.keyId)
    }

    @Test
    fun migratingReturnsNullWhenNeitherHasIdentity() = runBlocking {
        val store = MigratingProtectedSharingIdentityStore(FakeStore(), FakeStore())
        assertNull(store.load("easy-bc"))
    }

    /** A fake Drive that serves canned HTTP responses to the appdata store. */
    private class FakeDriveStore(
        private val responder: (url: String, method: String, body: ByteArray?) -> String,
    ) : DriveAppDataProtectedSharingIdentityStore(authorization = { Authorization("token") }) {
        override fun request(
            url: String,
            accessToken: String,
            method: String,
            contentType: String?,
            body: ByteArray?,
            extraHeaders: Map<String, String>,
        ): String = responder(url, method, body)
    }

    @Test
    fun appDataStoreReadsAndCreates() = runBlocking {
        val stored = record()
        val json = SyncKitJson.instance.encodeToString(
            ProtectedSharingIdentityV1.serializer(),
            stored,
        )
        var created = false
        val store = FakeDriveStore { url, method, _ ->
            when {
                url.contains("q=") && !created -> """{"files":[]}"""
                url.contains("q=") -> """{"files":[{"id":"file-1","name":"n"}]}"""
                url.contains("uploadType=multipart") && method == "POST" -> {
                    created = true; """{"id":"file-1"}"""
                }
                url.contains("alt=media") -> json
                else -> error("unexpected $method $url")
            }
        }
        assertNull(store.load("easy-bc"))
        store.save(stored)
        assertTrue(created)
        assertEquals(stored.publicKey.keyId, store.load("easy-bc")!!.publicKey.keyId)
    }
}
