package com.keyneom.synckit.stores

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class GoogleDriveFileStoreTest {
    @Test
    fun `response headers resolve case-insensitively as HTTP2 lowercases names`() {
        val headers = driveResponseHeaders(
            mapOf(
                null to listOf("HTTP/2 200"),
                "etag" to listOf("\"rev-42\""),
                "content-type" to listOf("application/json"),
            ),
        )
        assertEquals("\"rev-42\"", headers["ETag"])
        assertEquals("\"rev-42\"", headers["etag"])
        assertEquals("application/json", headers["Content-Type"])
        assertNull(headers["X-Missing"])
    }
}
