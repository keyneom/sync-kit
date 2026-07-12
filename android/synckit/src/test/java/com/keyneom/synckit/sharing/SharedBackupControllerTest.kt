package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.sharing.checkpoint.SharedDatasetHead
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.Json
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
    fun matchesFixedTypeScriptControlMergeAndUtf16OrderingVector() {
        val fixture = checkNotNull(javaClass.classLoader?.getResourceAsStream("sharing-v1/control-merge.json"))
            .bufferedReader().use { Json.parseToJsonElement(it.readText()).jsonObject }
        val codec = createSharingControlCodec()
        val merged = codec.merge(
            codec.parse(fixture["local"]!!),
            codec.parse(fixture["remote"]!!),
        )
        assertEquals(
            fixture["expectedEventIds"]!!.jsonArray.map { it.jsonPrimitive.content },
            merged.events.map { it.eventId },
        )
    }

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
    fun mixedCodecInvitationAcceptsAndReencryptsAppAndControlDatasets() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerRegistry = MemorySharedBackupRegistry()
        val recipientRegistry = MemorySharedBackupRegistry()
        val controlCodec = createSharingControlCodec()
        val ownerData = controller(owner, transport, ownerRegistry) { datasetId ->
            controlCodec.takeIf { datasetId == "profile-control" }
        }
        val recipientData = controller(recipient, transport, recipientRegistry) { datasetId ->
            controlCodec.takeIf { datasetId == "profile-control" }
        }
        val ownerControl = controlDataset(owner, transport, ownerRegistry, "owner")
        val recipientControl = controlDataset(recipient, transport, recipientRegistry, "recipient")

        val data = ownerData.createDataset("tasks", Payload(listOf("owner")))
        ownerControl.create(SharingControlMemberMetadataV1(email = "owner@example.test"))
        val invite = ownerData.inviteParticipantForLink(
            emailAddress = "recipient@example.test",
            requestedGrants = listOf(
                SharingDatasetGrantV1("tasks", SharingRole.VIEWER),
                SharingDatasetGrantV1("profile-control", SharingRole.WRITER),
            ),
        )
        val response = recipientData.submitKeyResponseFromInvitation(invite.invitation, invite.files)
        val accepted = ownerData.acceptKeyResponseFromPayload(
            invite.invitation,
            response,
            "recipient@example.test",
        )
        assertEquals(listOf("accepted", "accepted"), accepted.map { it.status })
        val cryptographicMember = ownerData.getDatasetParticipants("profile-control").participants
            .single { it.keyId == recipient.publicKey.keyId }
        assertEquals(invite.invitation.exchangeId, cryptographicMember.accepted?.exchangeId)
        assertEquals(invite.invitation.recipientDrivePermissionId, cryptographicMember.accepted?.drivePermissionId)

        ownerControl.synchronizeMembers(
            mapOf(recipient.publicKey.keyId to SharingControlMemberMetadataV1(email = "recipient@example.test")),
        )
        assertEquals(
            invite.invitation.recipientDrivePermissionId,
            recipientControl.read().members[recipient.publicKey.keyId]?.drivePermissionId,
        )
        ownerControl.announceMigration(
            SharingControlMigrationV1(
                migrationId = "split-tasks",
                sourceDatasetIds = listOf("tasks"),
                targets = listOf(SharingControlMigrationTargetV1("tasks", data.fileId, data.revisionId)),
                requiredAcks = listOf(
                    SharingControlMigrationRequirementV1(recipient.publicKey.keyId, listOf(data.fileId)),
                ),
            ),
        )
        val unauthorizedMember = runCatching {
            recipientControl.addMember(SharingControlMemberV1(SharingCrypto.generateIdentity().publicKey))
        }.exceptionOrNull()
        assertEquals(SyncKitErrorCode.AUTHORIZATION, (unauthorizedMember as SyncKitError).code)
        val unauthorizedMigration = runCatching {
            recipientControl.announceMigration(
                SharingControlMigrationV1("unauthorized", emptyList(), emptyList(), emptyList()),
            )
        }.exceptionOrNull()
        assertEquals(SyncKitErrorCode.AUTHORIZATION, (unauthorizedMigration as SyncKitError).code)
        val missing = runCatching { recipientControl.acknowledgeMigration("split-tasks", emptyList()) }.exceptionOrNull()
        assertEquals(SyncKitErrorCode.STATE, (missing as SyncKitError).code)
        val unexpected = runCatching {
            recipientControl.acknowledgeMigration("split-tasks", listOf(data.fileId, "other"))
        }.exceptionOrNull()
        assertEquals(SyncKitErrorCode.STATE, (unexpected as SyncKitError).code)
        val premature = runCatching { ownerControl.closeMigration("split-tasks") }.exceptionOrNull()
        assertEquals(SyncKitErrorCode.STATE, (premature as SyncKitError).code)

        assertEquals(listOf("owner"), recipientData.loadDataset("tasks").value.items)
        recipientControl.acknowledgeMigration("split-tasks", listOf(data.fileId))
        ownerControl.closeMigration("split-tasks")
        assertEquals(true, ownerControl.migrationStatus("split-tasks").closed)
        assertEquals(recipient.publicKey.keyId, ownerControl.read().members[recipient.publicKey.keyId]?.publicKey?.keyId)

        ownerControl.announceMigration(
            SharingControlMigrationV1(
                "forced-cutover",
                listOf("tasks"),
                listOf(SharingControlMigrationTargetV1("tasks", data.fileId)),
                listOf(SharingControlMigrationRequirementV1(owner.publicKey.keyId, listOf(data.fileId))),
            ),
        )
        val acknowledgementForAnotherKey = runCatching {
            recipientControl.acknowledgeMigration("forced-cutover", listOf(data.fileId))
        }.exceptionOrNull()
        assertEquals(SyncKitErrorCode.AUTHORIZATION, (acknowledgementForAnotherKey as SyncKitError).code)
        ownerControl.closeMigration("forced-cutover", force = true)
        assertEquals(true, ownerControl.migrationStatus("forced-cutover").closed)
    }

    @Test
    fun addDatasetParticipantUsesTheMixedCodecControlDataset() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerRegistry = MemorySharedBackupRegistry()
        val recipientRegistry = MemorySharedBackupRegistry()
        val controlCodec = createSharingControlCodec()
        val ownerData = controller(owner, transport, ownerRegistry) { datasetId ->
            controlCodec.takeIf { datasetId == "profile-control" }
        }
        val recipientData = controller(recipient, transport, recipientRegistry) { datasetId ->
            controlCodec.takeIf { datasetId == "profile-control" }
        }
        val ownerControl = controlDataset(owner, transport, ownerRegistry, "owner-direct")
        val recipientControl = controlDataset(recipient, transport, recipientRegistry, "recipient-direct")
        ownerControl.create(SharingControlMemberMetadataV1(email = "owner@example.test"))

        ownerData.addDatasetParticipant(
            datasetId = "profile-control",
            publicKey = recipient.publicKey,
            role = SharingRole.WRITER,
            emailAddress = "recipient@example.test",
        )

        recipientData.adoptDataset("profile-control")
        assertEquals(owner.publicKey.keyId, recipientControl.read().ownerKeyId)
    }

    @Test
    fun controlVerificationRejectsTamperingWrongOwnerAndConflictingEvents() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val registry = MemorySharedBackupRegistry()
        val control = controlDataset(owner, transport, registry, "owner")
        control.create(SharingControlMemberMetadataV1(email = "owner@example.test"))
        val state = control.read().state
        val genesis = state.events.single() as SharingControlMemberUpsertEventV1
        val tampered = state.copy(events = listOf(genesis.copy(member = genesis.member.copy(email = "attacker@example.test"))))
        assertEquals(
            SyncKitErrorCode.CRYPTO,
            (runCatching { verifySharingControlStateV1(tampered, owner.publicKey.keyId) }.exceptionOrNull() as SyncKitError).code,
        )
        assertEquals(
            SyncKitErrorCode.AUTHORIZATION,
            (runCatching { verifySharingControlStateV1(state, "repinned-owner") }.exceptionOrNull() as SyncKitError).code,
        )
        val conflicting = genesis.copy(createdAt = "2026-07-09T12:00:01Z")
        assertEquals(
            SyncKitErrorCode.CONFLICT,
            (runCatching { mergeSharingControlStates(state, state.copy(events = listOf(conflicting))) }.exceptionOrNull() as SyncKitError).code,
        )
        val wrongProfile = state.copy(profileId = "other-profile")
        assertEquals(
            SyncKitErrorCode.COMPATIBILITY,
            (runCatching { verifySharingControlStateV1(wrongProfile) }.exceptionOrNull() as SyncKitError).code,
        )
    }

    @Test
    fun completesLinkCarriedInviteResponseAndAcceptFlow() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerRegistry = MemorySharedBackupRegistry()
        val ownerController = controller(owner, transport, ownerRegistry)
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
    fun changesParticipantRoleAndDrivePermissionTogether() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerRegistry = MemorySharedBackupRegistry()
        val ownerController = controller(owner, transport, ownerRegistry)
        val recipientController = controller(recipient, transport, MemorySharedBackupRegistry())

        ownerController.createDataset("tasks", Payload(listOf("owner")))
        val invite = ownerController.inviteParticipantForLink(
            emailAddress = "recipient@example.com",
            requestedGrants = listOf(SharingDatasetGrantV1("tasks", SharingRole.WRITER)),
        )
        val response = recipientController.submitKeyResponseFromInvitation(
            invite.invitation,
            invite.files,
        )
        ownerController.acceptKeyResponseFromPayload(
            invitation = invite.invitation,
            response = response,
            recipientEmailAddress = "recipient@example.com",
        )
        val registryRecord = ownerRegistry.get("tasks") ?: error("Expected owner registry record.")
        ownerRegistry.set(registryRecord.copy(participantPermissionIds = emptyMap()))

        ownerController.setDatasetRole(
            datasetId = "tasks",
            keyId = recipient.publicKey.keyId,
            role = SharingRole.VIEWER,
            emailAddress = "recipient@example.com",
        )

        val stored = transport.readDataset("dataset-tasks")
        assertEquals(
            SharingRole.VIEWER,
            sharedBackupParticipant(stored.envelope, recipient.publicKey.keyId)?.role,
        )
        assertEquals(
            "reader",
            transport.listDatasetPermissions(stored.fileId).single().role,
        )
    }

    @Test
    fun revokesParticipantKeyAndTrackedDrivePermissionTogether() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerRegistry = MemorySharedBackupRegistry()
        val ownerController = controller(owner, transport, ownerRegistry)
        val recipientController = controller(recipient, transport, MemorySharedBackupRegistry())

        ownerController.createDataset("tasks", Payload(listOf("owner")))
        val invite = ownerController.inviteParticipantForLink(
            emailAddress = "recipient@example.com",
            requestedGrants = listOf(SharingDatasetGrantV1("tasks", SharingRole.WRITER)),
        )
        val response = recipientController.submitKeyResponseFromInvitation(
            invite.invitation,
            invite.files,
        )
        ownerController.acceptKeyResponseFromPayload(
            invitation = invite.invitation,
            response = response,
            recipientEmailAddress = "recipient@example.com",
        )
        val registryRecord = ownerRegistry.get("tasks") ?: error("Expected owner registry record.")
        ownerRegistry.set(registryRecord.copy(participantPermissionIds = emptyMap()))

        ownerController.revokeDatasetKey(
            datasetId = "tasks",
            keyId = recipient.publicKey.keyId,
            emailAddress = "recipient@example.com",
        )

        val stored = transport.readDataset("dataset-tasks")
        assertEquals(
            null,
            sharedBackupParticipant(stored.envelope, recipient.publicKey.keyId),
        )
        assertEquals(emptyList<SharedDatasetDrivePermission>(), transport.listDatasetPermissions(stored.fileId))
        assertEquals(
            "unchanged",
            ownerController.revokeDatasetKey(
                datasetId = "tasks",
                keyId = recipient.publicKey.keyId,
            ).outcome,
        )
    }

    @Test
    fun removesDriveAccessBeforeWritingRevocationEnvelope() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerController = controller(owner, transport, MemorySharedBackupRegistry())
        val recipientController = controller(recipient, transport, MemorySharedBackupRegistry())

        ownerController.createDataset("tasks", Payload(listOf("owner")))
        val invite = ownerController.inviteParticipantForLink(
            emailAddress = "recipient@example.com",
            requestedGrants = listOf(SharingDatasetGrantV1("tasks", SharingRole.WRITER)),
        )
        val response = recipientController.submitKeyResponseFromInvitation(
            invite.invitation,
            invite.files,
        )
        ownerController.acceptKeyResponseFromPayload(
            invitation = invite.invitation,
            response = response,
            recipientEmailAddress = "recipient@example.com",
        )

        transport.conflictNextWrite = true
        val error = try {
            ownerController.revokeDatasetKey(
                datasetId = "tasks",
                keyId = recipient.publicKey.keyId,
                emailAddress = "recipient@example.com",
            )
            null
        } catch (error: SyncKitError) {
            error
        }
        assertEquals(SyncKitErrorCode.CONFLICT, error?.code)

        val stored = transport.readDataset("dataset-tasks")
        assertEquals(
            SharingRole.WRITER,
            sharedBackupParticipant(stored.envelope, recipient.publicKey.keyId)?.role,
        )
        assertEquals(emptyList<SharedDatasetDrivePermission>(), transport.listDatasetPermissions(stored.fileId))
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

    @Test
    fun trashDatasetMovesTheFileToTrashAndForgetsTheRecord() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val registry = MemorySharedBackupRegistry()
        val ownerController = controller(owner, transport, registry)
        ownerController.createDataset("tasks", Payload(listOf("owner")))

        ownerController.trashDataset("tasks")

        assertEquals(emptyList<SharedDatasetFile>(), ownerController.listDatasets())
        assertEquals(null, registry.get("tasks"))
        assertEquals(setOf("dataset-tasks"), transport.trashed)
    }

    @Test
    fun addDatasetParticipantGrantsAccessToKnownPublicKeyWithoutExchange() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerController = controller(owner, transport, MemorySharedBackupRegistry())
        ownerController.createDataset("tasks", Payload(listOf("owner")))

        ownerController.addDatasetParticipant(
            datasetId = "tasks",
            publicKey = recipient.publicKey,
            role = SharingRole.WRITER,
            emailAddress = "recipient@example.com",
        )

        val recipientController = controller(recipient, transport, MemorySharedBackupRegistry())
        val adopted = recipientController.adoptDataset("tasks")
        assertEquals(listOf("owner"), adopted.value.items)
        val stored = transport.readDataset("dataset-tasks")
        assertEquals(
            SharingRole.WRITER,
            sharedBackupParticipant(stored.envelope, recipient.publicKey.keyId)?.role,
        )
    }

    @Test
    fun addDatasetParticipantReusesInheritedReadAccessForViewers() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerController = controller(owner, transport, MemorySharedBackupRegistry())
        ownerController.createDataset("tasks", Payload(listOf("owner")))

        ownerController.addDatasetParticipant(
            datasetId = "tasks",
            publicKey = recipient.publicKey,
            role = SharingRole.VIEWER,
            emailAddress = "recipient@example.com",
        )

        assertEquals(emptyList<SharedDatasetDrivePermission>(), transport.listDatasetPermissions("dataset-tasks"))
        assertEquals(
            SharingRole.VIEWER,
            sharedBackupParticipant(
                transport.readDataset("dataset-tasks").envelope,
                recipient.publicKey.keyId,
            )?.role,
        )
    }

    @Test
    fun addDatasetParticipantDoesNotGrantDriveAclWhenSignedWriteFails() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerController = controller(owner, transport, MemorySharedBackupRegistry())
        ownerController.createDataset("tasks", Payload(listOf("owner")))
        transport.conflictNextWrite = true

        val error = runCatching {
            ownerController.addDatasetParticipant(
                datasetId = "tasks",
                publicKey = recipient.publicKey,
                role = SharingRole.WRITER,
                emailAddress = "recipient@example.com",
            )
        }.exceptionOrNull()

        assertEquals(SyncKitErrorCode.CONFLICT, (error as? SyncKitError)?.code)
        assertEquals(emptyList<SharedDatasetDrivePermission>(), transport.listDatasetPermissions("dataset-tasks"))
        assertEquals(
            null,
            sharedBackupParticipant(
                transport.readDataset("dataset-tasks").envelope,
                recipient.publicKey.keyId,
            ),
        )
    }

    @Test
    fun addDatasetParticipantUpsertsRoleWhenKeyAlreadyGranted() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerController = controller(owner, transport, MemorySharedBackupRegistry())
        ownerController.createDataset("tasks", Payload(listOf("owner")))
        ownerController.addDatasetParticipant(
            datasetId = "tasks",
            publicKey = recipient.publicKey,
            role = SharingRole.VIEWER,
            emailAddress = "recipient@example.com",
        )

        ownerController.addDatasetParticipant(
            datasetId = "tasks",
            publicKey = recipient.publicKey,
            role = SharingRole.WRITER,
            emailAddress = "recipient@example.com",
        )

        val stored = transport.readDataset("dataset-tasks")
        val granted = sharedBackupParticipants(stored.envelope)
            .filter { it.keyId == recipient.publicKey.keyId }
        assertEquals(1, granted.size)
        assertEquals(SharingRole.WRITER, granted.single().role)
    }

    @Test
    fun addDatasetParticipantRejectsNonAdministeringActor() = runBlocking {
        val owner = SharingCrypto.generateIdentity()
        val recipient = SharingCrypto.generateIdentity()
        val stranger = SharingCrypto.generateIdentity()
        val transport = MemorySharingTransport()
        val ownerController = controller(owner, transport, MemorySharedBackupRegistry())
        ownerController.createDataset("tasks", Payload(listOf("owner")))
        ownerController.addDatasetParticipant(
            datasetId = "tasks",
            publicKey = recipient.publicKey,
            role = SharingRole.VIEWER,
            emailAddress = "recipient@example.com",
        )

        val recipientController = controller(recipient, transport, MemorySharedBackupRegistry())
        recipientController.adoptDataset("tasks")
        val error = try {
            recipientController.addDatasetParticipant(
                datasetId = "tasks",
                publicKey = stranger.publicKey,
                role = SharingRole.VIEWER,
                emailAddress = "stranger@example.com",
            )
            null
        } catch (error: SyncKitError) {
            error
        }
        assertEquals(SyncKitErrorCode.AUTHORIZATION, error?.code)
    }

    private fun controller(
        identity: SharingIdentity,
        transport: SharedBackupTransport,
        registry: SharedBackupRegistry,
        codecForDataset: ((String) -> SharedBackupControllerCodec<*>?)? = null,
    ): SharedBackupController<Payload> = SharedBackupController(
        appId = "controller-test",
        codec = payloadCodec,
        codecForDataset = codecForDataset,
        identity = { identity },
        transport = transport,
        registry = registry,
        cryptoOptions = SharingCryptoOptions(
            now = { java.util.Date.from(java.time.Instant.parse("2026-07-01T12:00:00.000Z")) },
            randomUuid = { "generated-${++uuidCounter}" },
        ),
    )

    private fun controlDataset(
        identity: SharingIdentity,
        transport: SharedBackupTransport,
        registry: SharedBackupRegistry,
        prefix: String,
    ): SharingControlDataset = SharingControlDataset(
        controller = SharedBackupController(
            appId = "controller-test",
            codec = createSharingControlCodec(),
            identity = { identity },
            transport = transport,
            registry = registry,
            cryptoOptions = SharingCryptoOptions(
                now = { java.util.Date.from(java.time.Instant.parse("2026-07-09T12:00:00.000Z")) },
                randomUuid = { "$prefix-controller-${++uuidCounter}" },
            ),
        ),
        datasetId = "profile-control",
        profileId = "profile-1",
        identity = { identity },
        now = { java.time.Instant.parse("2026-07-09T12:00:00.000Z") },
        randomUuid = { "$prefix-event-${++uuidCounter}" },
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
        var conflictNextWrite = false
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
            if (conflictNextWrite) {
                conflictNextWrite = false
                throw SyncKitError(SyncKitErrorCode.CONFLICT, "Conflict")
            }
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

        val trashed = mutableSetOf<String>()
        override suspend fun trashDataset(fileId: String) {
            datasets.remove(fileId)
            trashed.add(fileId)
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
            val driveRole = if (role == SharingRole.VIEWER) "reader" else "writer"
            if (existingDirectPermissionId == null &&
                role == SharingRole.VIEWER &&
                hasInheritedReadAccess
            ) {
                return SharedDatasetPermission(role = driveRole)
            }
            val permissionId = existingDirectPermissionId ?: "permission-$emailAddress"
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
