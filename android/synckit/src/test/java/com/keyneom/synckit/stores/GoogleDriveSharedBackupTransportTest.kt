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
    fun writeDatasetSkipsIfMatchForNonEtagVersions() = runBlocking {
        val first = envelope()
        val next = envelope(revisionId = "revision-2", previous = first)
        val current = VersionedSharedDataset(
            datasetId = "ds-1",
            fileId = "ds-file",
            name = "ds-1.sync-kit.json",
            envelope = first,
            version = "rev-7",
        )
        // Freshness preflight sees the same head we read.
        server.enqueue(json(metadataJson("rev-7")))
        // Upload returns no ETag, so the transport re-reads the dataset.
        server.enqueue(json("""{"id":"ds-file"}"""))
        server.enqueue(json(metadataJson("rev-8")))
        server.enqueue(json(envelopeJson(next)))

        val written = transport().writeDataset(current, next)

        assertEquals("rev-8", written.version)
        val requests = generateSequence { server.takeRequest(1, java.util.concurrent.TimeUnit.SECONDS) }
            .take(4)
            .toList()
        val upload: RecordedRequest = requests.first { it.method == "POST" }
        assertNull(upload.getHeader("If-Match"))
    }
}
