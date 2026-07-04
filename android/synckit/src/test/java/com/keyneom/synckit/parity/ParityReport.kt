package com.keyneom.synckit.parity

import com.keyneom.synckit.core.SyncCodec
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.PasskeyProfile
import com.keyneom.synckit.crypto.SyncEnvelopeV1
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.crypto.V1CompatibilityProfile
import com.keyneom.synckit.crypto.V1Compression
import com.keyneom.synckit.crypto.V1EnvelopeCrypto
import com.keyneom.synckit.crypto.V1KeyMetadata
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.security.MessageDigest

/**
 * Builds the same v1 parity report shape as `scripts/parity-v1-report.mjs`.
 */
object ParityReport {
    private val reportJson = Json {
        prettyPrint = false
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    private val secret = sequence(0, 32)
    private val salt = sequence(32, 32)
    private val nonce = sequence(64, 12)
    private val prfInput = sequence(96, 32)

    private val easyBcProfile = V1CompatibilityProfile(
        appId = "easy-bc",
        filename = "easybc-sync-v1.json",
        aad = "easy-bc-sync-envelope-v1",
        hkdfInfo = "easy-bc-cloud-content-key-v1",
        compression = V1Compression.GZIP_IF_SMALLER,
        passkey = PasskeyProfile("EasyBC", "encrypted-sync", "EasyBC encrypted sync"),
    )

    private val familyChoresProfile = V1CompatibilityProfile(
        appId = "family-chores",
        filename = "family-chores-sync-v1.json",
        aad = "family-chores-sync-envelope-v1",
        hkdfInfo = "family-chores-cloud-content-key-v1",
        compression = V1Compression.NONE,
        passkey = PasskeyProfile(
            "Family Chores",
            "encrypted-sync",
            "Family Chores encrypted sync",
        ),
    )

    private val codec = object : SyncCodec<JsonObject> {
        override fun serialize(value: JsonObject): ByteArray =
            // Match Node JSON.stringify key insertion order used by the JS report.
            utf8Json(value).toByteArray(Charsets.UTF_8)

        override fun parse(bytes: ByteArray): JsonObject =
            SyncKitJson.instance.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject

        override fun merge(local: JsonObject, remote: JsonObject): JsonObject = local

        override fun fingerprint(value: JsonObject): String = stableFingerprint(value)

        override fun updatedAt(value: JsonObject): String =
            value["exportedAt"]?.jsonPrimitive?.content
                ?: error("payload missing exportedAt")
    }

    private val easyBcCrypto = V1EnvelopeCrypto(easyBcProfile, codec)
    private val familyCrypto = V1EnvelopeCrypto(familyChoresProfile, codec)

    private val metadata = V1KeyMetadata(
        credentialId = "parity-credential",
        rpId = "keyneom.github.io",
        prfInput = prfInput,
        kdfSalt = salt,
    )

    private val smallPayload = jsonObject(
        "schemaVersion" to 1,
        "exportedAt" to "2026-07-04T00:00:00.000Z",
        "text" to "parity-vector",
    )

    private val compressiblePayload = jsonObject(
        "schemaVersion" to 1,
        "exportedAt" to "2026-07-04T00:00:00.000Z",
        "text" to "repeated private journal text ".repeat(200),
    )

    fun build(): Report {
        val easyBcKey = easyBcCrypto.deriveContentKey(secret, salt)
        val familyKey = familyCrypto.deriveContentKey(secret, salt)

        val easyBcUncompressed = loadFixture("easybc-web-uncompressed.json")
        val easyBcGzip = loadFixture("easybc-web-android-gzip.json")
        val familyChores = loadFixture("family-chores-web-uncompressed.json")
        val failures = loadJson("failures.json")

        val encryptUncompressed = easyBcCrypto.encryptWithNonce(
            smallPayload,
            easyBcKey,
            metadata,
            nonce,
        )
        val encryptFamilyChores = familyCrypto.encryptWithNonce(
            smallPayload,
            familyKey,
            metadata,
            nonce,
        )
        require(encryptUncompressed.compression == null) {
            "Expected small EasyBC parity payload to stay uncompressed."
        }
        require(encryptFamilyChores.compression == null) {
            "Expected Family Chores parity payload to stay uncompressed."
        }
        require(
            stableFingerprint(easyBcCrypto.decrypt(encryptUncompressed, easyBcKey)) ==
                stableFingerprint(smallPayload),
        )
        require(
            stableFingerprint(familyCrypto.decrypt(encryptFamilyChores, familyKey)) ==
                stableFingerprint(smallPayload),
        )

        val peerEnvelope = easyBcCrypto.encryptWithNonce(
            compressiblePayload,
            easyBcKey,
            metadata,
            nonce,
        )
        require(peerEnvelope.compression == "gzip") {
            "Expected compressible parity payload to use gzip."
        }

        val wrongKey = easyBcCrypto.deriveContentKey(sequence(224, 32), salt)

        return Report(
            version = 1,
            platform = "kotlin",
            identical = IdenticalSection(
                contentKeys = mapOf(
                    "easy-bc" to Base64Url.encode(easyBcKey),
                    "family-chores" to Base64Url.encode(familyKey),
                ),
                fixtureSummaries = mapOf(
                    "easybc-web-uncompressed" to summarize(easyBcUncompressed, easyBcCrypto),
                    "easybc-web-android-gzip" to summarize(easyBcGzip, easyBcCrypto),
                    "family-chores-web-uncompressed" to summarize(familyChores, familyCrypto),
                ),
                parseRejections = mapOf(
                    "shortPrfInput" to rejectParse(
                        easyBcUncompressed.envelope.copy(prfInput = "AA"),
                        easyBcCrypto,
                    ),
                    "malformedEnvelope" to rejectParse(
                        failures.jsonObject["malformedEnvelope"]!!,
                        easyBcCrypto,
                    ),
                    "wrongLengthNonce" to rejectParse(
                        easyBcUncompressed.envelope.copy(nonce = "AA"),
                        easyBcCrypto,
                    ),
                ),
                encryptUncompressed = encryptUncompressed,
                encryptFamilyChores = encryptFamilyChores,
                wrongSecretRejected = rejectDecrypt(
                    easyBcUncompressed.envelope,
                    wrongKey,
                    easyBcCrypto,
                ),
            ),
            peerChallenge = PeerChallenge(
                description =
                    "Compressed EasyBC envelope for the other platform to decrypt (gzip bytes may differ by platform).",
                profileAppId = "easy-bc",
                secret = Base64Url.encode(secret),
                envelope = peerEnvelope,
                payloadFingerprint = stableFingerprint(compressiblePayload),
            ),
        )
    }

    fun toJson(report: Report): String = reportJson.encodeToString(Report.serializer(), report)

    fun decryptPeerChallenge(peerJson: String): String {
        val peer = reportJson.decodeFromString(Report.serializer(), peerJson)
        val challenge = peer.peerChallenge
        require(challenge.profileAppId == "easy-bc")
        val key = easyBcCrypto.deriveContentKey(Base64Url.decode(challenge.secret), salt)
        val payload = try {
            easyBcCrypto.decrypt(challenge.envelope, key)
        } finally {
            key.fill(0)
        }
        val fingerprint = stableFingerprint(payload)
        require(fingerprint == challenge.payloadFingerprint) {
            "Peer payload fingerprint mismatch: $fingerprint != ${challenge.payloadFingerprint}"
        }
        return fingerprint
    }

    private fun summarize(fixture: FixtureFile, crypto: V1EnvelopeCrypto<JsonObject>): FixtureSummary {
        val key = crypto.deriveContentKey(
            Base64Url.decode(fixture.secret),
            Base64Url.decode(fixture.envelope.kdfSalt),
        )
        return try {
            val payload = crypto.decrypt(fixture.envelope, key)
            FixtureSummary(
                payloadFingerprint = stableFingerprint(payload),
                exportedAt = payload["exportedAt"]!!.jsonPrimitive.content,
                envelopeUpdatedAt = fixture.envelope.updatedAt,
                compression = fixture.envelope.compression,
                ciphertextSha256 = sha256Base64Url(fixture.envelope.ciphertext),
            )
        } finally {
            key.fill(0)
        }
    }

    private fun rejectParse(envelope: SyncEnvelopeV1, crypto: V1EnvelopeCrypto<JsonObject>): Rejection =
        try {
            crypto.validateEnvelope(envelope)
            Rejection(rejected = false)
        } catch (error: SyncKitError) {
            Rejection(rejected = true, code = error.code.name.lowercase().replace('_', '-'), message = error.message)
        } catch (error: Exception) {
            Rejection(rejected = true, code = "unknown", message = error.message)
        }

    private fun rejectParse(element: JsonElement, crypto: V1EnvelopeCrypto<JsonObject>): Rejection =
        try {
            val envelope = SyncKitJson.instance.decodeFromJsonElement(
                SyncEnvelopeV1.serializer(),
                element,
            )
            rejectParse(envelope, crypto)
        } catch (error: SyncKitError) {
            Rejection(rejected = true, code = error.code.name.lowercase().replace('_', '-'), message = error.message)
        } catch (error: Exception) {
            Rejection(rejected = true, code = "compatibility", message = error.message)
        }

    private fun rejectDecrypt(
        envelope: SyncEnvelopeV1,
        key: ByteArray,
        crypto: V1EnvelopeCrypto<JsonObject>,
    ): Rejection =
        try {
            crypto.decrypt(envelope, key)
            Rejection(rejected = false)
        } catch (error: SyncKitError) {
            Rejection(rejected = true, code = error.code.name.lowercase().replace('_', '-'), message = error.message)
        } catch (error: Exception) {
            Rejection(rejected = true, code = "unknown", message = error.message)
        }

    private fun loadFixture(name: String): FixtureFile =
        reportJson.decodeFromString(FixtureFile.serializer(), loadResource("v1/$name"))

    private fun loadJson(name: String): JsonObject =
        SyncKitJson.instance.parseToJsonElement(loadResource("v1/$name")).jsonObject

    private fun loadResource(path: String): String {
        val stream = ParityReport::class.java.classLoader.getResourceAsStream(path)
            ?: error("Missing test resource $path")
        return stream.use { it.readBytes().toString(Charsets.UTF_8) }
    }

    private fun sequence(start: Int, length: Int): ByteArray =
        ByteArray(length) { index -> ((start + index) and 0xff).toByte() }

    private fun jsonObject(vararg pairs: Pair<String, Any>): JsonObject = buildJsonObject {
        for ((key, value) in pairs) {
            when (value) {
                is Int -> put(key, value)
                is String -> put(key, value)
                else -> error("unsupported value type")
            }
        }
    }

    /**
     * Node `JSON.stringify` for our small objects: insertion order, no spaces.
     * Keys are emitted in the order supplied to [jsonObject].
     */
    private fun utf8Json(value: JsonObject): String = buildString {
        append('{')
        var first = true
        for ((key, element) in value) {
            if (!first) append(',')
            first = false
            append(JSONObjectQuote(key))
            append(':')
            append(jsonElementLiteral(element))
        }
        append('}')
    }

    private fun jsonElementLiteral(element: JsonElement): String = when (element) {
        is JsonPrimitive -> {
            val content = element.contentOrNull
            when {
                element.isString -> JSONObjectQuote(content!!)
                else -> content!!
            }
        }
        is JsonObject -> utf8Json(element)
        else -> error("unsupported json element")
    }

    private fun JSONObjectQuote(value: String): String =
        buildString {
            append('"')
            for (ch in value) {
                when (ch) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(ch)
                }
            }
            append('"')
        }

    private fun stableFingerprint(value: JsonObject): String =
        sha256Base64Url(canonicalJson(value))

    private fun canonicalJson(value: JsonElement): String = when (value) {
        JsonNull -> "null"
        is JsonPrimitive -> {
            if (value.isString) JSONObjectQuote(value.content) else value.content
        }
        is JsonArray -> value.joinToString(",", "[", "]") { canonicalJson(it) }
        is JsonObject -> {
            val keys = value.keys.sorted()
            keys.joinToString(",", "{", "}") { key ->
                "${JSONObjectQuote(key)}:${canonicalJson(value.getValue(key))}"
            }
        }
    }

    private fun sha256Base64Url(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return Base64Url.encode(digest)
    }

    @Serializable
    data class Report(
        val version: Int,
        val platform: String,
        val identical: IdenticalSection,
        val peerChallenge: PeerChallenge,
    )

    @Serializable
    data class IdenticalSection(
        val contentKeys: Map<String, String>,
        val fixtureSummaries: Map<String, FixtureSummary>,
        val parseRejections: Map<String, Rejection>,
        val encryptUncompressed: SyncEnvelopeV1,
        val encryptFamilyChores: SyncEnvelopeV1,
        val wrongSecretRejected: Rejection,
    )

    @Serializable
    data class FixtureSummary(
        val payloadFingerprint: String,
        val exportedAt: String,
        val envelopeUpdatedAt: String,
        val compression: String? = null,
        val ciphertextSha256: String,
    )

    @Serializable
    data class Rejection(
        val rejected: Boolean,
        val code: String? = null,
        val message: String? = null,
    )

    @Serializable
    data class PeerChallenge(
        val description: String,
        val profileAppId: String,
        val secret: String,
        val envelope: SyncEnvelopeV1,
        val payloadFingerprint: String,
    )

    @Serializable
    private data class FixtureFile(
        val secret: String,
        val envelope: SyncEnvelopeV1,
    )
}
