package com.keyneom.synckit.crypto

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class Base64UrlTest {
    @Test
    fun encodeIsUnpadded() {
        val encoded = Base64Url.encode(byteArrayOf(1, 2, 3))
        assertEquals(false, encoded.contains('='))
    }

    @Test
    fun decodeRejectsPaddedInput() {
        try {
            Base64Url.decode("AQID=")
            org.junit.Assert.fail("expected compatibility error")
        } catch (error: SyncKitError) {
            assertEquals(SyncKitErrorCode.COMPATIBILITY, error.code)
        }
    }

    @Test
    fun roundTripUnpaddedValues() {
        val bytes = ByteArray(32) { it.toByte() }
        assertArrayEquals(bytes, Base64Url.decode(Base64Url.encode(bytes)))
    }
}
