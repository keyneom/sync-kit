package com.keyneom.synckit.crypto

import com.keyneom.synckit.core.SyncCodec
import com.keyneom.synckit.core.SyncKitError
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class V1EnvelopeCryptoTest {
    private val profile = V1CompatibilityProfile(
        appId = "easy-bc",
        filename = "easybc-sync-v1.json",
        aad = "easy-bc-sync-envelope-v1",
        hkdfInfo = "easy-bc-cloud-content-key-v1",
        compression = V1Compression.GZIP_IF_SMALLER,
        passkey = PasskeyProfile(
            rpName = "EasyBC",
            userName = "encrypted-sync",
            userDisplayName = "EasyBC encrypted sync",
        ),
    )

    private val codec = object : SyncCodec<JsonObject> {
        override fun serialize(value: JsonObject): ByteArray =
            SyncKitJson.instance.encodeToString(JsonObject.serializer(), value)
                .toByteArray(Charsets.UTF_8)

        override fun parse(bytes: ByteArray): JsonObject =
            SyncKitJson.instance.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject

        override fun merge(local: JsonObject, remote: JsonObject): JsonObject = local

        override fun fingerprint(value: JsonObject): String =
            SyncKitJson.instance.encodeToString(JsonObject.serializer(), value)

        override fun updatedAt(value: JsonObject): String =
            value["exportedAt"]?.jsonPrimitive?.content
                ?: "1970-01-01T00:00:00.000Z"
    }

    private val crypto = V1EnvelopeCrypto(profile, codec)

    @Test
    fun decryptsSharedGzipCryptoVector() {
        val envelope = SyncEnvelopeV1(
            compression = "gzip",
            credentialId = "credential",
            rpId = "keyneom.github.io",
            prfInput = "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8",
            kdfSalt = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            nonce = "QEFCQ0RFRkdISUpL",
            ciphertext = "LMBOEaK5ATYQxI26eKGwIdJ_ELsBJ8rf76MIXyxVsT3kN1K3qY42h07AZHOYkztpJYdhERCZmbG2j_Pd1zhqKRMIMdrj_-pBd6DljWZU0uD7d5rHWCbyAqudt_psdPSHm47MuQauJTsCjVmEkPNKCZZNOZkYnceNyC9MZQM_tY15jJLsHEdOnQS43zyNhv180UmM9POJcsaWBAG6yIfDRDpd2b1IpPuxmIAV3GLMYLiNHbJ4yDUX6PRYFhzI-Hh18rggXBENhWfq9kZ3hBpPKGkms-j4MHFIGhg_o3GY_rZTHCzq3phTdD3Mo4iSWf7D6FXezQP6H_jwyhDE0ydJyTjNfIPPyCESZtc",
            updatedAt = "2026-06-22T12:00:00Z",
        )
        val secret = Base64Url.decode("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")

        val payload = crypto.decryptWithSecret(envelope, secret)

        assertEquals(
            "38",
            payload["planner"]!!.jsonObject["value"]!!.jsonObject["ageYears"]!!.jsonPrimitive.content,
        )
        assertTrue(
            payload["calendarDayLogs"]!!.jsonObject["2026-06-22"]!!.jsonObject["notes"]!!
                .jsonPrimitive.content.contains("cross-platform gzip vector"),
        )
    }

    @Test
    fun decryptsWebCryptoVector() {
        val envelope = SyncEnvelopeV1(
            credentialId = "credential",
            rpId = "keyneom.github.io",
            prfInput = "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8",
            kdfSalt = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            nonce = "QEFCQ0RFRkdISUpL",
            ciphertext = "SGk1csrcbFdGshJaXqUdM-SLg9O0ZjtkHuUREJkV5R89VrpDkTmr12IlZ5W6d4Qk4pQ0kVT9XO7F_r4OHtoWNGbjzrdv49y2LhT-uDLjzNu38r-xVoQXGU3HTJdvr6VFk18TbaKAN08gD3wluMP9JH_IKwpGHeAgZyoajp3agwg4bGV-VSw9URAFlHrXtgJKymwNPz_4E4UHbmjcnCK94JngZgqYXnhBueTwX4fTayIrzqXl_JEcGDm6aEcae_FoqhZ1dVUVx5KynVj_JRgPMKOtviGe-LLk7aXbCoRLxSjZDU4nlPQOV2dFkbrwpV6afwsu1IQWwZ-xvnDovfN8eHzVuvdb7JgSIShs62Yy5N-wgCm-BUWxHp5oq0LUFkGB2njyTQjkmSYBiM4eVOYvhBTIRNQZqFMXSEI32-NyCEaLvv63y43OkQ9-kpWKZ7-yDpM-Mcs5ckNk3IKTHTGhl_0DMpZxA5QONtGvDCW4SHr8dKEQ6aDQ",
            updatedAt = "2026-06-21T12:00:00Z",
        )
        val secret = Base64Url.decode("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")

        val payload = crypto.decryptWithSecret(envelope, secret)

        assertEquals(
            "37",
            payload["planner"]!!.jsonObject["value"]!!.jsonObject["ageYears"]!!.jsonPrimitive.content,
        )
        assertEquals("2026-06-21T12:00:00Z", payload["exportedAt"]!!.jsonPrimitive.content)
    }

    @Test
    fun rejectsOneBytePrfInput() {
        val envelope = SyncEnvelopeV1(
            credentialId = "credential",
            rpId = "keyneom.github.io",
            prfInput = "AA",
            kdfSalt = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
            nonce = "QEFCQ0RFRkdISUpL",
            ciphertext = "AAAA",
            updatedAt = "2026-06-21T12:00:00Z",
        )
        try {
            crypto.validateEnvelope(envelope)
            org.junit.Assert.fail("expected invalid PRF input length")
        } catch (error: SyncKitError) {
            assertTrue(error.message!!.contains("PRF input"))
        }
    }

    @Test
    fun roundTripsAndCompressesRepetitivePayload() {
        val payload = SyncKitJson.instance.parseToJsonElement(
            """
            {
              "schemaVersion": 1,
              "exportedAt": "2026-06-21T13:00:00Z",
              "planner": { "value": { "ageYears": 41 }, "updatedAt": "2026-06-21T13:00:00Z" },
              "notes": "${"repeated private journal text ".repeat(200)}"
            }
            """.trimIndent(),
        ).jsonObject
        val secret = ByteArray(32) { it.toByte() }
        val salt = ByteArray(32) { (it + 32).toByte() }
        val key = crypto.deriveContentKey(secret, salt)
        val metadata = V1KeyMetadata(
            credentialId = "credential",
            rpId = "keyneom.github.io",
            prfInput = ByteArray(32) { 7 },
            kdfSalt = salt,
        )
        val envelope = crypto.encryptWithNonce(
            payload,
            key,
            metadata,
            ByteArray(12) { (it + 64).toByte() },
        )

        assertEquals("gzip", envelope.compression)
        assertEquals(payload, crypto.decrypt(envelope, key))
        assertNull(
            crypto.encryptWithNonce(
                SyncKitJson.instance.parseToJsonElement(
                    """{"exportedAt":"2026-06-21T13:00:00Z","x":1}""",
                ).jsonObject,
                key,
                metadata,
                ByteArray(12) { (it + 64).toByte() },
            ).compression,
        )
    }
}
