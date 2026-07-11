package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.atomic.AtomicInteger

class AccountBindingTest {
    @Test
    fun verifiesSharedTypeScriptKotlinGoldenBinding() = runBlocking {
        val text = javaClass.classLoader
            ?.getResourceAsStream("sharing-v1/account-binding.json")
            ?.use { it.readBytes().toString(Charsets.UTF_8) }
            ?: error("Missing sharing-v1/account-binding.json test resource.")
        val root = SyncKitJson.instance.parseToJsonElement(text).jsonObject
        val contextJson = root["context"]!!.jsonObject
        val verification = root["verification"]!!.jsonObject
        val binding = SyncKitJson.instance.decodeFromJsonElement(
            SharingAccountBindingV1.serializer(),
            root["binding"]!!,
        )
        val keys = root["jwks"]!!.jsonObject["keys"]!!.jsonArray.map { it.jsonObject }
        val account = SharingAccountBindings.verify(
            binding,
            SharingAccountBindingContext(
                contextJson["appId"]!!.jsonPrimitive.content,
                contextJson["exchangeId"]!!.jsonPrimitive.content,
                contextJson["sharingKeyId"]!!.jsonPrimitive.content,
                contextJson["credentialId"]!!.jsonPrimitive.content,
            ),
            verification["googleAudience"]!!.jsonPrimitive.content,
            verification["rpId"]!!.jsonPrimitive.content,
            verification["allowedOrigins"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet(),
            CachingGoogleJwksProvider(GoogleJwksFetcher { GoogleJwksResponse(keys) }),
            nowMillis = { verification["nowMillis"]!!.jsonPrimitive.content.toLong() },
        )
        assertEquals("google-subject", account.subject)
    }

    @Test
    fun challengeMatchesTypeScriptGoldenValue() {
        val challenge = SharingAccountBindings.createChallenge(
            SharingAccountBindingContext(
                appId = "fixture-app",
                exchangeId = "exchange-1",
                sharingKeyId = Base64Url.encode(ByteArray(32) { 9 }),
                credentialId = "Y3JlZGVudGlhbC0x",
            ),
        )
        assertEquals("F0Pvn8fvoDOa12henhD0jhdyLzQdMdOcEdrjSwu7-lU", challenge)
    }

    @Test
    fun verifiesWebAuthnAndGoogleSignaturesTogether() = runBlocking {
        val context = SharingAccountBindingContext(
            "fixture-app",
            "exchange-1",
            Base64Url.encode(ByteArray(32) { 9 }),
            "Y3JlZGVudGlhbC0x",
        )
        val challenge = SharingAccountBindings.createChallenge(context)
        val credentialKeys = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val credentialPublic = credentialKeys.public as ECPublicKey
        val credentialJwk = buildJsonObject {
            put("kty", "EC")
            put("crv", "P-256")
            put("x", Base64Url.encode(fixed32(credentialPublic.w.affineX.toByteArray())))
            put("y", Base64Url.encode(fixed32(credentialPublic.w.affineY.toByteArray())))
        }
        val clientBytes = """{"type":"webauthn.get","challenge":"$challenge","origin":"android:apk-key-hash:release"}"""
            .toByteArray()
        val authenticatorData = ByteArray(37).also {
            MessageDigest.getInstance("SHA-256").digest("example.test".toByteArray()).copyInto(it)
            it[32] = 0x05
        }
        val signed = authenticatorData + MessageDigest.getInstance("SHA-256").digest(clientBytes)
        val passkeySignature = Signature.getInstance("SHA256withECDSA").run {
            initSign(credentialKeys.private)
            update(signed)
            sign()
        }

        val googleKeys = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val googlePublic = googleKeys.public as RSAPublicKey
        val googleJwk = buildJsonObject {
            put("kty", "RSA")
            put("kid", "fixture-google-key")
            put("n", Base64Url.encode(unsigned(googlePublic.modulus.toByteArray())))
            put("e", Base64Url.encode(unsigned(googlePublic.publicExponent.toByteArray())))
        }
        val header = Base64Url.encode("""{"alg":"RS256","kid":"fixture-google-key"}""".toByteArray())
        val payload = Base64Url.encode(
            """{"iss":"https://accounts.google.com","aud":"google-client-id","sub":"google-subject","email":"recipient@example.com","email_verified":true,"nonce":"$challenge","iat":1899999900,"exp":2000000000}""".toByteArray(),
        )
        val jwtSignature = Signature.getInstance("SHA256withRSA").run {
            initSign(googleKeys.private)
            update("$header.$payload".toByteArray())
            sign()
        }
        val binding = SharingAccountBindings.createV1(
            challenge,
            "$header.$payload.${Base64Url.encode(jwtSignature)}",
            SharingPasskeyAssertionV1(
                context.credentialId,
                credentialJwk,
                Base64Url.encode(authenticatorData),
                Base64Url.encode(clientBytes),
                Base64Url.encode(passkeySignature),
            ),
        )
        val fetches = AtomicInteger()
        val jwks = CachingGoogleJwksProvider(
            fetcher = GoogleJwksFetcher {
                fetches.incrementAndGet()
                GoogleJwksResponse(listOf(googleJwk), 3_600)
            },
            nowMillis = { 1_900_000_000_000 },
        )

        val account = SharingAccountBindings.verify(
            binding,
            context,
            googleAudience = "google-client-id",
            rpId = "example.test",
            allowedOrigins = setOf("android:apk-key-hash:release"),
            jwks = jwks,
            nowMillis = { 1_900_000_000_000 },
        )
        assertEquals("google-subject", account.subject)
        assertEquals("recipient@example.com", account.email)
        SharingAccountBindings.verify(
            binding,
            context,
            "google-client-id",
            "example.test",
            setOf("android:apk-key-hash:release"),
            jwks,
            nowMillis = { 1_900_000_000_000 },
        )
        assertEquals(1, fetches.get())

        val wrongOrigin = runCatching {
            SharingAccountBindings.verifyPasskey(
                binding.passkey,
                challenge,
                "example.test",
                setOf("android:apk-key-hash:debug"),
            )
        }.exceptionOrNull() as SyncKitError
        assertEquals(SyncKitErrorCode.AUTHORIZATION, wrongOrigin.code)
    }

    @Test
    fun unknownKidForcesOneRefreshThenRejects() = runBlocking {
        val calls = AtomicInteger()
        val provider = CachingGoogleJwksProvider(
            fetcher = GoogleJwksFetcher {
                calls.incrementAndGet()
                GoogleJwksResponse(listOf(buildJsonObject {
                    put("kty", "RSA")
                    put("kid", "another-key")
                }))
            },
        )
        assertEquals(null, provider.key("missing-key"))
        assertEquals(2, calls.get())
    }

    @Test
    fun androidOriginsDoNotDoubleHashFingerprints() {
        val fingerprint = ByteArray(32) { it.toByte() }
        assertEquals(
            "android:apk-key-hash:${Base64Url.encode(fingerprint)}",
            androidApkKeyHashOriginFromSha256(fingerprint),
        )
        val hex = fingerprint.joinToString(":") { "%02X".format(it.toInt() and 0xff) }
        assertEquals(androidApkKeyHashOriginFromSha256(fingerprint), androidApkKeyHashOriginFromHexSha256(hex))
        assertTrue(androidApkKeyHashOrigin("certificate".toByteArray()).startsWith("android:apk-key-hash:"))
    }

    private fun fixed32(value: ByteArray): ByteArray = unsigned(value).let {
        if (it.size == 32) it else ByteArray(32 - it.size) + it
    }

    private fun unsigned(value: ByteArray): ByteArray =
        if (value.size > 1 && value[0] == 0.toByte()) value.copyOfRange(1, value.size) else value
}
