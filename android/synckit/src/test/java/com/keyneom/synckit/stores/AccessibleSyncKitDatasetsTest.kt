package com.keyneom.synckit.stores

import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.TimeUnit

class AccessibleSyncKitDatasetsTest {
    private lateinit var server: MockWebServer

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
    fun `shared fixture filters deduplicates paginates and sorts exactly`() = runBlocking {
        val fixtureText = checkNotNull(
            javaClass.classLoader?.getResourceAsStream("sharing-v1/accessible-datasets.json"),
        ).bufferedReader().use { it.readText() }
        val fixture = SyncKitJson.instance.parseToJsonElement(fixtureText).jsonObject
        fixture.getValue("pages").jsonArray.forEach { page ->
            server.enqueue(
                MockResponse()
                    .setHeader("Content-Type", "application/json")
                    .setBody(page.toString()),
            )
        }
        val origin = server.url("/").toString().trimEnd('/')
        val actual = listAccessibleSyncKitDatasets(
            ListAccessibleSyncKitDatasetsOptions(
                appId = fixture.getValue("appId").jsonPrimitive.content,
                authorization = Authorization("token"),
                drive = GoogleDriveFileStore(
                    GoogleDriveStoreOptions(apiOrigin = origin, uploadOrigin = origin),
                ),
            ),
        )
        val expected = fixture.getValue("expected").jsonArray.map { element ->
            val value = element.jsonObject
            AccessibleSyncKitDataset(
                datasetId = value.getValue("datasetId").jsonPrimitive.content,
                fileId = value.getValue("fileId").jsonPrimitive.content,
                name = value.getValue("name").jsonPrimitive.content,
                appFolderId = value["appFolderId"]?.jsonPrimitive?.content,
                canEdit = value["canEdit"]?.jsonPrimitive?.booleanOrNull,
                modifiedTime = value["modifiedTime"]?.jsonPrimitive?.content,
            )
        }

        assertEquals(expected, actual)

        val requests = generateSequence { server.takeRequest(1, TimeUnit.SECONDS) }
            .take(2)
            .toList()
        assertEquals(2, requests.size)
        assertTrue(requests.all { it.method == "GET" })
        val firstQuery = requests[0].requestUrl?.queryParameter("q").orEmpty()
        assertTrue(firstQuery.contains("key='sync-kit-app-id' and value='fixture-app'"))
        assertTrue(firstQuery.contains("key='sync-kit-protocol' and value='sharing-v1'"))
        assertTrue(firstQuery.contains("key='sync-kit-kind' and value='dataset'"))
        assertEquals("page-2", requests[1].requestUrl?.queryParameter("pageToken"))
    }

    @Test
    fun `blank app id fails before a Drive request`() {
        val origin = server.url("/").toString().trimEnd('/')
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                listAccessibleSyncKitDatasets(
                    ListAccessibleSyncKitDatasetsOptions(
                        appId = " ",
                        authorization = Authorization("token"),
                        drive = GoogleDriveFileStore(
                            GoogleDriveStoreOptions(apiOrigin = origin, uploadOrigin = origin),
                        ),
                    ),
                )
            }
        }
        assertEquals(0, server.requestCount)
    }
}
