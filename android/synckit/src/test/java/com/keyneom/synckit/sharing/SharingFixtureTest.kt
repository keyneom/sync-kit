package com.keyneom.synckit.sharing

import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.CanonicalJson
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.sharing.checkpoint.SharedDatasetHead
import com.keyneom.synckit.sharing.checkpoint.SharingNotificationEventKind
import com.keyneom.synckit.sharing.checkpoint.SharingSyncCheckpoint
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SharingFixtureTest {
    @Test
    fun webcryptoOwnerViewerFixtureDecryptAndSignature() {
        val fixtureText = javaClass.classLoader
            ?.getResourceAsStream("sharing-v1/webcrypto-owner-viewer.json")
            ?.use { it.readBytes().toString(Charsets.UTF_8) }
            ?: error("Missing sharing-v1/webcrypto-owner-viewer.json test resource.")
        val root = SyncKitJson.instance.parseToJsonElement(fixtureText).jsonObject
        val viewer = root["viewer"]!!.jsonObject
        val viewerPublic = viewer["publicKey"]!!.jsonObject
        val encryptionPrivate = viewer["privateKeys"]!!.jsonObject["encryption"]!!.jsonObject
        val envelopeJson = root["envelope"]!!.jsonObject
        val envelope = SharingCrypto.parseSharedBackupEnvelopeV1(
            SyncKitJson.instance.decodeFromJsonElement(
                SharedBackupEnvelopeV1.serializer(),
                envelopeJson,
            ),
        )
        val publicKey = SharingPublicKeyV1(
            keyId = viewerPublic["keyId"]!!.jsonPrimitive.content,
            encryptionAlgorithm = viewerPublic["encryptionAlgorithm"]!!.jsonPrimitive.content,
            encryptionPublicKey = viewerPublic["encryptionPublicKey"]!!.jsonPrimitive.content,
            signatureAlgorithm = viewerPublic["signatureAlgorithm"]!!.jsonPrimitive.content,
            signingPublicKey = viewerPublic["signingPublicKey"]!!.jsonPrimitive.content,
        )
        val identity = SharingEcKeys.identityFromPrivateKeyD(
            encryptionD = Base64Url.decode(encryptionPrivate["d"]!!.jsonPrimitive.content),
            signingD = Base64Url.decode(
                viewer["privateKeys"]!!.jsonObject["signing"]!!.jsonObject["d"]!!.jsonPrimitive.content,
            ),
            publicKey = publicKey,
        )
        val payload = SharingCrypto.decryptSharedBackupEnvelopeV1(
            envelope = envelope,
            codec = object : SharedBackupCodec<FixturePayload> {
                override fun serialize(value: FixturePayload) = buildJsonObject {
                    put("profile", value.profile)
                    put("count", value.count)
                }

                override fun parse(value: kotlinx.serialization.json.JsonElement): FixturePayload {
                    val obj = value.jsonObject
                    return FixturePayload(
                        profile = obj["profile"]!!.jsonPrimitive.content,
                        count = obj["count"]!!.jsonPrimitive.int,
                    )
                }
            },
            identity = identity,
        )
        val expectedPayload = root["payload"]!!.jsonObject
        assertEquals(
            CanonicalJson.encode(expectedPayload),
            CanonicalJson.encode(
                buildJsonObject {
                    put("profile", payload.profile)
                    put("count", payload.count)
                },
            ),
        )
        SharingCrypto.verifySharedBackupEnvelopeV1(envelope)
    }

    @Test
    fun webOwnershipTransferFixtureVerifiesAndDecryptsOnKotlin() {
        val root = javaClass.classLoader
            ?.getResourceAsStream("sharing-v1/ownership-transfer-wire.json")
            ?.use { SyncKitJson.instance.parseToJsonElement(it.readBytes().toString(Charsets.UTF_8)) }
            ?.jsonObject
            ?: error("Missing sharing-v1/ownership-transfer-wire.json test resource.")
        val recipient = root.getValue("recipient").jsonObject
        val public = recipient.getValue("publicKey").jsonObject
        val privateKeys = recipient.getValue("privateKeys").jsonObject
        val identity = SharingEcKeys.identityFromPrivateKeyD(
            encryptionD = Base64Url.decode(
                privateKeys.getValue("encryption").jsonObject.getValue("d").jsonPrimitive.content,
            ),
            signingD = Base64Url.decode(
                privateKeys.getValue("signing").jsonObject.getValue("d").jsonPrimitive.content,
            ),
            publicKey = SharingPublicKeyV1(
                keyId = public.getValue("keyId").jsonPrimitive.content,
                encryptionAlgorithm = public.getValue("encryptionAlgorithm").jsonPrimitive.content,
                encryptionPublicKey = public.getValue("encryptionPublicKey").jsonPrimitive.content,
                signatureAlgorithm = public.getValue("signatureAlgorithm").jsonPrimitive.content,
                signingPublicKey = public.getValue("signingPublicKey").jsonPrimitive.content,
            ),
        )
        val after = SyncKitJson.instance.decodeFromJsonElement(
            SharedBackupEnvelopeV1.serializer(),
            root.getValue("after"),
        )
        val ownerKeyId = root.getValue("owner").jsonObject
            .getValue("publicKey").jsonObject
            .getValue("keyId").jsonPrimitive.content

        SharingCrypto.verifySharedBackupEnvelopeV1(
            after,
            VerifySharedBackupOptions(trustedOwnerKeyId = ownerKeyId),
        )
        val payload = SharingCrypto.decryptSharedBackupEnvelopeV1(
            after,
            object : SharedBackupCodec<FixturePayload> {
                override fun serialize(value: FixturePayload) = buildJsonObject {
                    put("profile", value.profile)
                    put("count", value.count)
                }

                override fun parse(value: JsonElement): FixturePayload {
                    val obj = value.jsonObject
                    return FixturePayload(
                        obj.getValue("profile").jsonPrimitive.content,
                        obj.getValue("count").jsonPrimitive.int,
                    )
                }
            },
            identity,
            VerifySharedBackupOptions(trustedOwnerKeyId = ownerKeyId),
        )
        assertEquals("synthetic-sharing-fixture", payload.profile)
        assertEquals(1, payload.count)
        assertEquals("ownership-transfer-fixture", after.accessControl.last().ownershipTransfer?.transferId)
    }

    private data class FixturePayload(val profile: String, val count: Int)
}

class SharingChangeDetectorTest {
    @Test
    fun emitsPendingKeyResponsesForUnseenExchangeFiles() = runBlocking {
        val result = detectSharingChanges(
            listKeyResponses = {
                listOf(
                    KeyResponseRef("response-1", "exchange-1"),
                    KeyResponseRef("response-2", "exchange-2"),
                )
            },
            listDatasetHeads = { emptyList() },
            checkpoint = SharingSyncCheckpoint(lastSeenKeyResponseFileIds = listOf("response-1")),
            options = SharingChangeDetectorOptions(
                now = { java.util.Date.from(java.time.Instant.parse("2026-07-01T12:00:00.000Z")) },
            ),
        )
        assertEquals(
            listOf(
                SharingNotificationEventKind.PendingKeyResponse("exchange-2", "response-2"),
            ),
            result.events,
        )
        assertEquals(
            listOf("response-1", "response-2"),
            result.checkpoint.lastSeenKeyResponseFileIds,
        )
        assertEquals("2026-07-01T12:00:00Z", result.checkpoint.lastPollAt)
    }

    @Test
    fun emitsSharedDatasetChangedWhenHeadSignatureChanges() = runBlocking {
        val previousHead = SharedDatasetHead(
            datasetId = "tasks",
            fileId = "file-1",
            etag = "\"1\"",
        )
        val result = detectSharingChanges(
            listKeyResponses = { emptyList() },
            listDatasetHeads = {
                listOf(
                    SharedDatasetHead(
                        datasetId = "tasks",
                        fileId = "file-1",
                        etag = "\"2\"",
                    ),
                )
            },
            checkpoint = SharingSyncCheckpoint(datasetHeads = mapOf("tasks" to previousHead)),
            options = SharingChangeDetectorOptions(
                now = { java.util.Date.from(java.time.Instant.parse("2026-07-01T12:00:00.000Z")) },
            ),
        )
        assertEquals(
            listOf(
                SharingNotificationEventKind.SharedDatasetChanged("tasks", "file-1"),
            ),
            result.events,
        )
        assertEquals("\"2\"", result.checkpoint.datasetHeads?.get("tasks")?.etag)
    }

    @Test
    fun returnsTokenExpiredWithoutPolling() = runBlocking {
        var polled = false
        val result = detectSharingChanges(
            listKeyResponses = {
                polled = true
                emptyList()
            },
            listDatasetHeads = {
                polled = true
                emptyList()
            },
            checkpoint = SharingSyncCheckpoint(),
            options = SharingChangeDetectorOptions(
                now = { java.util.Date.from(java.time.Instant.parse("2026-07-01T12:00:00.000Z")) },
                tokenExpiresAt = java.time.Instant.parse("2026-07-01T11:59:59.000Z").toEpochMilli(),
            ),
        )
        assertFalse(polled)
        assertEquals(listOf(SharingNotificationEventKind.TokenExpired), result.events)
    }

    @Test
    fun buildsDetectorFromTransport() = runBlocking {
        val detector = createSharingChangeDetectorFromTransport(
            object : SharedBackupTransport by MockTransport() {
                override suspend fun listExchanges(
                    exchangeId: String?,
                    kind: String?,
                ): List<SharedExchangeFile> = listOf(
                    SharedExchangeFile(
                        fileId = "response-1",
                        exchangeId = "exchange-1",
                        kind = "key-response",
                    ),
                )

                override suspend fun listDatasetHeads(): List<SharedDatasetHead> = listOf(
                    SharedDatasetHead(datasetId = "tasks", fileId = "file-1", etag = "\"1\""),
                )
            },
        )
        val result = detector.detect(SharingSyncCheckpoint())
        assertEquals(
            listOf(
                SharingNotificationEventKind.PendingKeyResponse("exchange-1", "response-1"),
            ),
            result.events,
        )
        assertEquals("file-1", result.checkpoint.datasetHeads?.get("tasks")?.fileId)
    }
}

private open class MockTransport : SharedBackupTransport {
    override suspend fun ensureStorage(): SharedBackupStorage =
        error("not implemented")

    override suspend fun listDatasets(): List<SharedDatasetFile> = emptyList()
    override suspend fun readDataset(fileId: String): VersionedSharedDataset =
        error("not implemented")

    override suspend fun createDataset(
        datasetId: String,
        envelope: SharedBackupEnvelopeV1,
    ): VersionedSharedDataset = error("not implemented")

    override suspend fun writeDataset(
        current: VersionedSharedDataset,
        envelope: SharedBackupEnvelopeV1,
    ): VersionedSharedDataset = error("not implemented")

    override suspend fun grantExchangeAccess(
        emailAddress: String,
        sendNotificationEmail: Boolean?,
        emailMessage: String?,
    ): ExchangeAccessResult = error("not implemented")

    override suspend fun createInvitation(invitation: SharingInvitationV1): String =
        error("not implemented")

    override suspend fun createKeyResponse(response: SharingPublicKeyResponseV1): String =
        error("not implemented")

    override suspend fun listExchanges(
        exchangeId: String?,
        kind: String?,
    ): List<SharedExchangeFile> = emptyList()

    override suspend fun readInvitation(fileId: String): SharingInvitationV1 =
        error("not implemented")

    override suspend fun readKeyResponse(
        fileId: String,
        expectedDrivePermissionId: String,
    ): SharedKeyResponseFile = error("not implemented")

    override suspend fun deleteExchange(fileId: String) = Unit
    override suspend fun setDatasetPermission(
        fileId: String,
        emailAddress: String,
        role: SharingRole,
        existingDirectPermissionId: String?,
        hasInheritedReadAccess: Boolean,
    ): SharedDatasetPermission = error("not implemented")

    override suspend fun removeDatasetPermission(fileId: String, permissionId: String) = Unit
    override suspend fun listDatasetPermissions(fileId: String): List<SharedDatasetDrivePermission> =
        emptyList()

    override suspend fun listDatasetHeads(): List<SharedDatasetHead> = emptyList()
}
