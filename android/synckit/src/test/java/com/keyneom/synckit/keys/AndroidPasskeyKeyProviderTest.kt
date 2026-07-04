package com.keyneom.synckit.keys

import android.app.Activity
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.PasskeyProfile
import com.keyneom.synckit.crypto.SyncEnvelopeV1
import com.keyneom.synckit.crypto.V1CompatibilityProfile
import com.keyneom.synckit.crypto.V1Compression
import com.keyneom.synckit.crypto.V1EnvelopeCrypto
import com.keyneom.synckit.crypto.V1KeyMetadata
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidPasskeyKeyProviderTest {
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
    private val activity = Activity()
    private val secret = ByteArray(32) { (it + 1).toByte() }
    private val salt = ByteArray(32) { 2 }
    private val prfInput = ByteArray(32) { 3 }
    private val metadata = V1KeyMetadata("credential", "example.com", prfInput, salt)

    @Test
    fun prfResultFromResponseParsesFirstSecret() {
        val encoded = Base64Url.encode(secret)
        val response = buildJsonObject {
            put(
                "clientExtensionResults",
                buildJsonObject {
                    put(
                        "prf",
                        buildJsonObject {
                            put(
                                "results",
                                buildJsonObject {
                                    put("first", encoded)
                                },
                            )
                        },
                    )
                },
            )
        }
        assertArrayEquals(secret, AndroidPasskeyKeyProvider.prfResultFromResponse(response))
    }

    @Test
    fun prfResultFromResponseReturnsNullWhenMissing() {
        assertNull(AndroidPasskeyKeyProvider.prfResultFromResponse(buildJsonObject {}))
    }

    @Test
    fun prfExtensionsMatchWebAuthnShape() {
        val extensions = AndroidPasskeyKeyProvider.prfExtensions("prf-input")
        val prf = extensions["prf"]!!.toString()
        assertTrue(prf.contains("eval"))
        assertTrue(prf.contains("first"))
        assertTrue(prf.contains("prf-input"))
    }

    @Test
    fun coalescesConcurrentUnlocksForSameEnvelope() = runBlocking {
        val unlockCalls = AtomicInteger(0)
        val provider = TestPasskeyProvider(unlockCalls)
        val envelope = fixtureEnvelope()

        val first = async { provider.unlock(activity, envelope) }
        val second = async { provider.unlock(activity, envelope) }

        val a = first.await()
        val b = second.await()

        assertEquals(1, unlockCalls.get())
        assertArrayEquals(a, b)
        assertTrue(provider.isUnlockedFor(envelope))
    }

    @Test
    fun rejectsMismatchedRpIdBeforeUnlock() = runBlocking {
        val provider = TestPasskeyProvider(AtomicInteger(0))
        val envelope = fixtureEnvelope().copy(rpId = "other.example")
        try {
            provider.unlock(activity, envelope)
            org.junit.Assert.fail("expected compatibility error")
        } catch (error: SyncKitError) {
            assertEquals(SyncKitErrorCode.COMPATIBILITY, error.code)
        }
    }

    private fun fixtureEnvelope(): SyncEnvelopeV1 {
        val key = crypto.deriveContentKey(secret, salt)
        return crypto.encrypt("remote", key, metadata)
    }

    private inner class TestPasskeyProvider(
        private val unlockCalls: AtomicInteger,
    ) : AndroidPasskeyKeyProvider<String>(profile, "example.com", crypto) {
        override suspend fun unlockPrf(
            activity: Activity,
            credentialId: String,
            prfInput: String,
        ): ByteArray {
            unlockCalls.incrementAndGet()
            return secret.copyOf()
        }
    }
}
