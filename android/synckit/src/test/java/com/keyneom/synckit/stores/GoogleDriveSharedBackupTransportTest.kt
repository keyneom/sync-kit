package com.keyneom.synckit.stores

import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.core.AuthorizationProvider
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.sharing.CreateSharedBackupEnvelopeInput
import com.keyneom.synckit.sharing.SharedBackupCodec
import com.keyneom.synckit.sharing.SharedBackupEnvelopeV1
import com.keyneom.synckit.sharing.SharedBackupParticipantInput
import com.keyneom.synckit.sharing.SharingCrypto
import com.keyneom.synckit.sharing.SharingIdentity
import com.keyneom.synckit.sharing.SharingRole
import com.keyneom.synckit.sharing.VersionedSharedDataset
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Drive v3 does not reliably send HTTP ETags (never over Android's HTTP/2
 * connections), so the transport must fall back to metadata change tokens
 * and must not leave orphan files behind when a create cannot be read back.
 */
class GoogleDriveSharedBackupTransportTest {
    private lateinit var server: MockWebServer
    private lateinit var identity: SharingIdentity

    private val codec = object : SharedBackupCodec<String> {
        override fun serialize(value: String): JsonElement = JsonPrimitive(value)
        override fun parse(value: JsonElement): String = value.jsonPrimitive.content
    }

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        identity = SharingCrypto.generateIdentity()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun transport(): GoogleDriveSharedBackupTransport {
        val origin = server.url("/").toString().trimEnd('/')
        return GoogleDriveSharedBackupTransport(
            appId = "fixture-app",
            authorizationProvider = object : AuthorizationProvider {
                override suspend fun authorize(): Authorization = Authorization("token")
            },
            selectedAppFolderId = "app-folder",
            drive = GoogleDriveFileStore(
                GoogleDriveStoreOptions(apiOrigin = origin, uploadOrigin = origin),
            ),
        )
    }

    private fun envelope(
        revisionId: String = "revision-1",
        previous: SharedBackupEnvelopeV1? = null,
    ): SharedBackupEnvelopeV1 = SharingCrypto.createSharedBackupEnvelopeV1(
        value = "payload",
        codec = codec,
        identity = identity,
        input = CreateSharedBackupEnvelopeInput(
            appId = "fixture-app",
            backupId = "ds-1",
            participants = listOf(
                SharedBackupParticipantInput(
                    publicKey = identity.publicKey,
                    role = SharingRole.OWNER,
                ),
            ),
            previous = previous,
            revisionId = revisionId,
        ),
    )

    private fun envelopeJson(value: SharedBackupEnvelopeV1): String =
        SyncKitJson.instance.encodeToString(SharedBackupEnvelopeV1.serializer(), value)

    private fun metadataJson(headRevisionId: String): String = """
        {
          "id": "ds-file",
          "name": "ds-1.sync-kit.json",
          "headRevisionId": "$headRevisionId",
          "version": "3",
          "appProperties": {
            "sync-kit-app-id": "fixture-app",
            "sync-kit-protocol": "sharing-v1",
            "sync-kit-kind": "dataset",
            "sync-kit-dataset-id": "ds-1"
          }
        }
    """.trimIndent()

    private fun json(body: String): MockResponse =
        MockResponse().setBody(body).setHeader("Content-Type", "application/json")

    @Test
    fun readDatasetFallsBackToHeadRevisionIdWithoutEtagHeader() = runBlocking {
        server.enqueue(json(metadataJson("rev-7")))
        server.enqueue(json(envelopeJson(envelope())))

        val dataset = transport().readDataset("ds-file")

        assertEquals("rev-7", dataset.version)
        assertEquals("ds-1", dataset.datasetId)
    }

    @Test
    fun listDatasetsIsReadOnlyForSelectedAppFolder() = runBlocking {
        server.enqueue(json("""{"files":[]}"""))

        assertEquals(emptyList<com.keyneom.synckit.sharing.SharedDatasetFile>(), transport().listDatasets())

        val request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)
            ?: error("No Drive list request was issued.")
        assertEquals("GET", request.method)
        assertTrue(request.requestUrl?.queryParameter("q").orEmpty().contains("'app-folder' in parents"))
        assertEquals(1, server.requestCount)
    }

    @Test
    fun listDatasetsDoesNotCreateStorageWhenAppRootIsMissing() = runBlocking {
        server.enqueue(json("""{"files":[]}"""))
        val origin = server.url("/").toString().trimEnd('/')
        val transport = GoogleDriveSharedBackupTransport(
            appId = "fixture-app",
            authorizationProvider = object : AuthorizationProvider {
                override suspend fun authorize(): Authorization = Authorization("token")
            },
            drive = GoogleDriveFileStore(
                GoogleDriveStoreOptions(apiOrigin = origin, uploadOrigin = origin),
            ),
        )

        assertEquals(emptyList<com.keyneom.synckit.sharing.SharedDatasetFile>(), transport.listDatasets())

        val request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)
            ?: error("No Drive list request was issued.")
        assertEquals("GET", request.method)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun createDatasetDeletesOrphanWhenReadBackFails() = runBlocking {
        // ensureStorage (selectedAppFolderId set): exchanges folder lookup only.
        server.enqueue(json("""{"files":[{"id":"exchanges","name":"exchanges"}]}"""))
        // Upload succeeds, then the read-back content cannot be parsed.
        server.enqueue(json("""{"id":"orphan-file"}"""))
        server.enqueue(json(metadataJson("rev-1")))
        server.enqueue(json("not-an-envelope"))
        // Rollback delete.
        server.enqueue(MockResponse().setResponseCode(204))

        val transport = transport()
        assertThrows(Exception::class.java) {
            runBlocking { transport.createDataset("ds-1", envelope()) }
        }

        val requests = generateSequence { server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS) }
            .take(5)
            .toList()
        val delete = requests.lastOrNull { it.method == "DELETE" }
            ?: error("No DELETE request was issued for the orphan file.")
        assertTrue(delete.path.orEmpty().contains("orphan-file"))
    }

    @Test
    fun writeDatasetUsesV2ConditionalWrites() = runBlocking {
        val first = envelope()
        val next = envelope(revisionId = "revision-2", previous = first)
        val current = VersionedSharedDataset(
            datasetId = "ds-1",
            fileId = "ds-file",
            name = "ds-1.sync-kit.json",
            envelope = first,
            version = "rev-7",
        )
        server.enqueue(
            json("""{"etag":"\"rev-7-etag\"","headRevisionId":"rev-7"}"""),
        )
        server.enqueue(
            json("""{"id":"ds-file","etag":"\"rev-8-etag\"","headRevisionId":"rev-8"}"""),
        )

        val written = transport().writeDataset(current, next)

        assertEquals("rev-8", written.version)
        val requests = generateSequence { server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS) }
            .take(2)
            .toList()
        assertTrue(requests[0].path.orEmpty().contains("/drive/v2/files/"))
        val upload = requests[1]
        assertEquals("PUT", upload.method)
        assertEquals("\"rev-7-etag\"", upload.getHeader("If-Match"))
    }

    @Test
    fun writeDatasetRejectsStaleV2IfMatch() {
        runBlocking {
            val first = envelope()
            val next = envelope(revisionId = "revision-2", previous = first)
            val current = VersionedSharedDataset(
                datasetId = "ds-1",
                fileId = "ds-file",
                name = "ds-1.sync-kit.json",
                envelope = first,
                version = "rev-7",
            )
            server.enqueue(
                json("""{"etag":"\"rev-7-etag\"","headRevisionId":"rev-7"}"""),
            )
            server.enqueue(MockResponse().setResponseCode(412))

            assertThrows(Exception::class.java) {
                runBlocking { transport().writeDataset(current, next) }
            }
        }
    }

    @Test
    fun trashDatasetUsesMetadataPatchOverride() = runBlocking {
        server.enqueue(json("{}"))

        transport().trashDataset("retired-dataset")

        val request = server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS)
            ?: error("No trash request was issued.")
        assertTrue(request.path.orEmpty().contains("/retired-dataset?supportsAllDrives=true"))
        assertEquals("POST", request.method)
        assertEquals("PATCH", request.getHeader("X-HTTP-Method-Override"))
        assertEquals("{\"trashed\":true}", request.body.readUtf8())
    }

    @Test
    fun writeDatasetFallsBackToV3WhenV2Unavailable() = runBlocking {
        val first = envelope()
        val next = envelope(revisionId = "revision-2", previous = first)
        val current = VersionedSharedDataset(
            datasetId = "ds-1",
            fileId = "ds-file",
            name = "ds-1.sync-kit.json",
            envelope = first,
            version = "rev-7",
        )
        server.enqueue(MockResponse().setResponseCode(404))
        server.enqueue(json(metadataJson("rev-7")))
        server.enqueue(json("""{"id":"ds-file"}"""))
        server.enqueue(json(metadataJson("rev-8")))
        server.enqueue(json(envelopeJson(next)))

        val written = transport().writeDataset(current, next)

        assertEquals("rev-8", written.version)
        val requests = generateSequence { server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS) }
            .take(5)
            .toList()
        assertTrue(requests[0].path.orEmpty().contains("/drive/v2/files/"))
        assertTrue(requests[1].path.orEmpty().contains("/drive/v3/files/"))
        val upload = requests[2]
        assertNull(upload.getHeader("If-Match"))
    }
}
