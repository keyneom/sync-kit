package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.sharing.checkpoint.SharedDatasetHead
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Test

class SharedBackupControllerTest {
    @Test
    fun completesInviteResponseAcceptAndReadFlow() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerRegistry = MemorySharedBackupRegistry()
        val recipientRegistry = MemorySharedBackupRegistry()
        val ownerController = controller(owner, transport, ownerRegistry)
        val recipientController = controller(recipient, transport, recipientRegistry)

        ownerController.createDataset("tasks", Payload(listOf("owner")))
        val invited = ownerController.inviteParticipant(
            InviteParticipantInput(
                emailAddress = "recipient@example.com",
                requestedGrants = listOf(
                    SharingDatasetGrantV1("tasks", SharingRole.WRITER),
                ),
                expiresAt = "2026-07-08T12:00:00.000Z",
            ),
        )
        val (responseFileId, _) = recipientController.submitKeyResponse(
            invited.invitationFileId,
        )
        val accepted = ownerController.acceptKeyResponse(
            invitation = invited.invitation,
            responseFileId = responseFileId,
            recipientEmailAddress = "recipient@example.com",
        )

        assertEquals(1, accepted.size)
        assertEquals("tasks", accepted[0].datasetId)
        assertEquals("accepted", accepted[0].status)
        assertEquals("permission-recipient@example.com", accepted[0].permissionId)

        val loaded = recipientController.loadDataset("tasks")
        assertEquals(listOf("owner"), loaded.value.items)
        assertEquals("loaded", loaded.outcome)

        val synced = recipientController.syncDataset(
            "tasks",
            Payload(listOf("owner", "recipient")),
        )
        assertEquals(listOf("owner", "recipient"), synced.value.items)
        assertEquals("updated", synced.outcome)
    }

    @Test
    fun completesLinkCarriedInviteResponseAndAcceptFlow() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerController = controller(owner, transport, MemorySharedBackupRegistry())
        val recipientController = controller(recipient, transport, MemorySharedBackupRegistry())
        val landing = "https://keyneom.github.io/easy-bc/"

        ownerController.createDataset("tasks", Payload(listOf("owner")))

        // Owner: per-email share + signed invitation, embedded in a link.
        val invite = ownerController.inviteParticipantForLink(
            emailAddress = "recipient@example.com",
            requestedGrants = listOf(SharingDatasetGrantV1("tasks", SharingRole.WRITER)),
        )
        assertEquals(1, invite.files.size)
        assertEquals("tasks", invite.files[0].datasetId)
        val joinLink = buildSharingJoinLinkV1(landing, invite.invitation, invite.files)

        // Recipient: parse link, produce a response link. No Drive exchange read.
        val parsedJoin = parseSharingJoinLinkV1(joinLink)!!
        val response = recipientController.submitKeyResponseFromInvitation(
            parsedJoin.invitation,
            parsedJoin.files,
        )
        val responseLink = buildSharingResponseLinkV1(landing, response)

        // Owner: parse response link, accept (keyGrant + per-email share).
        val parsedResponse = parseSharingResponseLinkV1(responseLink)!!
        val accepted = ownerController.acceptKeyResponseFromPayload(
            invitation = invite.invitation,
            response = parsedResponse.response,
            recipientEmailAddress = "recipient@example.com",
        )
        assertEquals(1, accepted.size)
        assertEquals("accepted", accepted[0].status)

        // Recipient can now read and write the dataset — no exchange files touched.
        val loaded = recipientController.loadDataset("tasks")
        assertEquals(listOf("owner"), loaded.value.items)
        val synced = recipientController.syncDataset(
            "tasks",
            Payload(listOf("owner", "recipient")),
        )
        assertEquals(listOf("owner", "recipient"), synced.value.items)
        assertEquals("updated", synced.outcome)
    }

    @Test
    fun adoptDatasetRecoversAnOwnedDatasetWithoutARegistryRecord() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        controller(owner, transport, MemorySharedBackupRegistry())
            .createDataset("tasks", Payload(listOf("owner")))

        // Same identity, empty registry: an interrupted setup or reinstall.
        val adopted = controller(owner, transport, MemorySharedBackupRegistry())
            .adoptDataset("tasks", requireOwned = true)

        assertEquals(listOf("owner"), adopted.value.items)
        assertEquals("adopted", adopted.outcome)
    }

    @Test
    fun adoptDatasetRequireOwnedRejectsNonOwners() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val stranger = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        controller(owner, transport, MemorySharedBackupRegistry())
            .createDataset("tasks", Payload(listOf("owner")))

        val error = try {
            controller(stranger, transport, MemorySharedBackupRegistry())
                .adoptDataset("tasks", requireOwned = true)
            null
        } catch (error: SyncKitError) {
            error
        }
        assertEquals(SyncKitErrorCode.AUTHORIZATION, error?.code)
    }

    @Test
    fun deleteDatasetRemovesTheFileAndLocalRecord() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val registry = MemorySharedBackupRegistry()
        val ownerController = controller(owner, transport, registry)
        ownerController.createDataset("tasks", Payload(listOf("owner")))

        ownerController.deleteDataset("tasks")

        assertEquals(emptyList<SharedDatasetFile>(), ownerController.listDatasets())
        assertEquals(null, registry.get("tasks"))
    }

    private fun controller(
        identity: SharingIdentity,
        transport: SharedBackupTransport,
        registry: SharedBackupRegistry,
    ): SharedBackupController<Payload> = SharedBackupController(
        appId = "controller-test",
        codec = payloadCodec,
        identity = { identity },
        transport = transport,
        registry = registry,
        cryptoOptions = SharingCryptoOptions(
            now = { java.util.Date.from(java.time.Instant.parse("2026-07-01T12:00:00.000Z")) },
            randomUuid = { "generated-${++uuidCounter}" },
        ),
    )

    private data class Payload(val items: List<String>)

    private val payloadCodec = object : SharedBackupControllerCodec<Payload> {
        override fun serialize(value: Payload): JsonElement = buildJsonObject {
            put("items", buildJsonArray { value.items.forEach { add(JsonPrimitive(it)) } })
        }

        override fun parse(value: JsonElement): Payload {
            val items = value.jsonObject["items"]!!.jsonArray.map { it.jsonPrimitive.content }
            return Payload(items)
        }

        override fun merge(local: Payload, remote: Payload): Payload =
            Payload((local.items + remote.items).distinct())

        override fun fingerprint(value: Payload): String =
            value.items.sorted().joinToString(",")
    }

    private class MemorySharingTransport : SharedBackupTransport {
        val storage = SharedBackupStorage("app-folder", "exchanges-folder")
        private val datasets = mutableMapOf<String, VersionedSharedDataset>()
        private val invitations = mutableMapOf<String, SharingInvitationV1>()
        private val responses = mutableMapOf<String, SharingPublicKeyResponseV1>()
        private val permissions = mutableMapOf<String, MutableMap<String, SharedDatasetDrivePermission>>()
        private var counter = 0

        override suspend fun ensureStorage(): SharedBackupStorage = storage

        override suspend fun listDatasets(): List<SharedDatasetFile> =
            datasets.values.map {
                SharedDatasetFile(it.datasetId, it.fileId, it.name, it.canEdit)
            }

        override suspend fun readDataset(fileId: String): VersionedSharedDataset =
            datasets[fileId] ?: error("Missing $fileId")

        override suspend fun createDataset(
            datasetId: String,
            envelope: SharedBackupEnvelopeV1,
        ): VersionedSharedDataset {
            val fileId = "dataset-$datasetId"
            val stored = VersionedSharedDataset(
                datasetId = datasetId,
                fileId = fileId,
                name = "$datasetId.sync-kit.json",
                canEdit = true,
                envelope = envelope,
                version = "\"${++counter}\"",
            )
            datasets[fileId] = stored
            return stored
        }

        override suspend fun writeDataset(
            current: VersionedSharedDataset,
            envelope: SharedBackupEnvelopeV1,
        ): VersionedSharedDataset {
            val updated = current.copy(
                envelope = envelope,
                version = "\"${++counter}\"",
            )
            datasets[current.fileId] = updated
            return updated
        }

        override suspend fun deleteDataset(fileId: String) {
            datasets.remove(fileId)
        }

        override suspend fun grantExchangeAccess(
            emailAddress: String,
            sendNotificationEmail: Boolean?,
            emailMessage: String?,
        ): ExchangeAccessResult = ExchangeAccessResult(
            drivePermissionId = "permission-$emailAddress",
            appFolderId = storage.appFolderId,
        )

        override suspend fun createInvitation(invitation: SharingInvitationV1): String {
            val fileId = "invitation-${invitation.exchangeId}"
            invitations[fileId] = invitation
            return fileId
        }

        override suspend fun createKeyResponse(response: SharingPublicKeyResponseV1): String {
            val fileId = "response-${response.exchangeId}"
            responses[fileId] = response
            return fileId
        }

        override suspend fun listExchanges(
            exchangeId: String?,
            kind: String?,
        ): List<SharedExchangeFile> {
            val invitationFiles = invitations.map { (fileId, invitation) ->
                SharedExchangeFile(fileId, invitation.exchangeId, "invitation")
            }
            val responseFiles = responses.map { (fileId, response) ->
                SharedExchangeFile(fileId, response.exchangeId, "key-response", response.keyId)
            }
            return (invitationFiles + responseFiles).filter { file ->
                (exchangeId == null || file.exchangeId == exchangeId) &&
                    (kind == null || file.kind == kind)
            }
        }

        override suspend fun readInvitation(fileId: String): SharingInvitationV1 =
            invitations[fileId] ?: error("Missing $fileId")

        override suspend fun readKeyResponse(
            fileId: String,
            expectedDrivePermissionId: String,
        ): SharedKeyResponseFile {
            val response = responses[fileId] ?: error("Missing $fileId")
            return SharedKeyResponseFile(
                fileId = fileId,
                response = response,
                ownerPermissionId = expectedDrivePermissionId,
            )
        }

        override suspend fun deleteExchange(fileId: String) {
            invitations.remove(fileId)
            responses.remove(fileId)
        }

        override suspend fun setDatasetPermission(
            fileId: String,
            emailAddress: String,
            role: SharingRole,
            existingDirectPermissionId: String?,
            hasInheritedReadAccess: Boolean,
        ): SharedDatasetPermission {
            if (role == SharingRole.VIEWER && hasInheritedReadAccess) {
                return SharedDatasetPermission(role = "reader")
            }
            val permissionId = existingDirectPermissionId ?: "permission-$emailAddress"
            val driveRole = if (role == SharingRole.VIEWER) "reader" else "writer"
            val filePermissions = permissions.getOrPut(fileId) { mutableMapOf() }
            filePermissions[permissionId] = SharedDatasetDrivePermission(
                permissionId = permissionId,
                role = driveRole,
                emailAddress = emailAddress,
                inherited = false,
            )
            return SharedDatasetPermission(permissionId = permissionId, role = driveRole)
        }

        override suspend fun removeDatasetPermission(fileId: String, permissionId: String) {
            permissions[fileId]?.remove(permissionId)
        }

        override suspend fun listDatasetPermissions(
            fileId: String,
        ): List<SharedDatasetDrivePermission> =
            permissions[fileId]?.values?.toList() ?: emptyList()

        override suspend fun listDatasetHeads(): List<SharedDatasetHead> =
            datasets.values.map {
                SharedDatasetHead(
                    datasetId = it.datasetId,
                    fileId = it.fileId,
                    version = it.version,
                    etag = it.version,
                )
            }
    }

    companion object {
        private var uuidCounter = 0
    }
}
