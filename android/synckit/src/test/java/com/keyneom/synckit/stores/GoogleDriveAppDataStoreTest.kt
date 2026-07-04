package com.keyneom.synckit.stores

import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.PasskeyProfile
import com.keyneom.synckit.crypto.V1CompatibilityProfile
import com.keyneom.synckit.crypto.V1Compression
import com.keyneom.synckit.crypto.V1EnvelopeCrypto
import com.keyneom.synckit.crypto.V1KeyMetadata
import java.net.URLDecoder
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class GoogleDriveAppDataStoreTest {
    private lateinit var server: MockWebServer
    private val auth = Authorization("token")

    private val profile = V1CompatibilityProfile(
        appId = "demo",
        filename = "demo-sync-v1.json",
        aad = "demo-aad",
        hkdfInfo = "demo-hkdf",
        compression = V1Compression.NONE,
        passkey = PasskeyProfile("Demo", "sync", "Demo sync"),
    )

    private val codec = object : com.keyneom.synckit.core.SyncCodec<String> {
        override fun serialize(value: String): ByteArray = value.toByteArray()
        override fun parse(bytes: ByteArray): String = bytes.toString(Charsets.UTF_8)
        override fun merge(local: String, remote: String): String =
            if (local >= remote) local else remote
        override fun fingerprint(value: String): String = value
        override fun updatedAt(value: String): String = "2026-07-04T00:00:00.000Z"
    }

    private val crypto = V1EnvelopeCrypto(profile, codec)

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun escapeDriveQueryEscapesQuotesAndBackslashes() {
        assertEquals(
            "app\\'s sync.json",
            GoogleDriveAppDataStore.escapeDriveQuery("app's sync.json"),
        )
        assertEquals(
            "path\\\\file.json",
            GoogleDriveAppDataStore.escapeDriveQuery("path\\file.json"),
        )
    }

    @Test
    fun findUsesEscapedFilenameInDriveQuery() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"files":[]}"""))
        val quotedProfile = profile.copy(filename = "app's sync.json")
        val store = GoogleDriveAppDataStore(
            quotedProfile,
            V1EnvelopeCrypto(quotedProfile, codec),
            storeOptions(),
        )
        assertEquals(null, store.find(quotedProfile.appId, auth))
        val request = server.takeRequest()
        val decoded = URLDecoder.decode(
            request.requestUrl!!.queryParameter("q")!!,
            Charsets.UTF_8.name(),
        )
        assertTrue(decoded.contains("name = 'app\\'s sync.json' and trashed = false"))
    }

    @Test
    fun updateExistingFileUsesPostWithPatchOverride() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"id":"existing"}"""))
        val store = GoogleDriveAppDataStore(profile, crypto, storeOptions())
        val secret = ByteArray(32) { 1 }
        val salt = ByteArray(32) { 2 }
        val prfInput = ByteArray(32) { 3 }
        val key = crypto.deriveContentKey(secret, salt)
        val metadata = V1KeyMetadata("credential", "example.com", prfInput, salt)
        val envelope = crypto.encrypt("payload", key, metadata)

        val fileId = store.write(profile.appId, envelope, auth, existingId = "existing")

        val request = server.takeRequest()
        assertEquals("existing", fileId)
        assertEquals("POST", request.method)
        assertEquals("PATCH", request.getHeader("X-HTTP-Method-Override"))
        assertTrue(request.path!!.contains("/upload/drive/v3/files/existing"))
    }

    @Test
    fun unauthorizedResponseInvokesCallbackAndMapsErrorCode() = runBlocking {
        var unauthorized = false
        server.enqueue(MockResponse().setResponseCode(401).setBody("expired"))
        val store = GoogleDriveAppDataStore(
            profile,
            crypto,
            storeOptions(onUnauthorized = { unauthorized = true }),
        )
        try {
            store.find(profile.appId, auth)
            org.junit.Assert.fail("expected authorization error")
        } catch (error: SyncKitError) {
            assertEquals(SyncKitErrorCode.AUTHORIZATION, error.code)
        }
        assertTrue(unauthorized)
    }

    @Test
    fun notFoundResponseMapsToNotFoundErrorCode() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(404))
        val store = GoogleDriveAppDataStore(profile, crypto, storeOptions())
        try {
            store.delete(profile.appId, "missing", auth)
            org.junit.Assert.fail("expected not-found error")
        } catch (error: SyncKitError) {
            assertEquals(SyncKitErrorCode.NOT_FOUND, error.code)
        }
    }

    @Test
    fun rejectsCrossAppAccessBeforeNetwork() = runBlocking {
        val store = GoogleDriveAppDataStore(profile, crypto, storeOptions())
        try {
            store.find("other-app", auth)
            org.junit.Assert.fail("expected configuration error")
        } catch (error: SyncKitError) {
            assertEquals(SyncKitErrorCode.CONFIGURATION, error.code)
        }
        assertFalse(server.requestCount > 0)
    }

    private fun storeOptions(onUnauthorized: (() -> Unit)? = null): GoogleDriveAppDataStoreOptions {
        val origin = server.url("").toString().trimEnd('/')
        return GoogleDriveAppDataStoreOptions(
            apiOrigin = origin,
            uploadOrigin = origin,
            onUnauthorized = onUnauthorized,
        )
    }
}
