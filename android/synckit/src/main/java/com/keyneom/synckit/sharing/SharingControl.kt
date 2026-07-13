package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.CanonicalJson
import java.time.Instant
import java.util.UUID
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put

const val SHARING_CONTROL_KIND = "sync-kit-sharing-control"
const val SHARING_CONTROL_EVENT_KIND = "sync-kit-sharing-control-event"

data class SharingControlMemberV1(
    val publicKey: SharingPublicKeyV1,
    val email: String? = null,
    val googleSubject: String? = null,
    val drivePermissionId: String? = null,
)

data class SharingControlMemberMetadataV1(
    val email: String? = null,
    val googleSubject: String? = null,
    val drivePermissionId: String? = null,
)

data class SharingControlMigrationTargetV1(
    val datasetId: String,
    val fileId: String,
    val revisionId: String? = null,
)

data class SharingControlMigrationRequirementV1(
    val keyId: String,
    val targetFileIds: List<String>,
)

data class SharingControlMigrationV1(
    val migrationId: String,
    val sourceDatasetIds: List<String>,
    val targets: List<SharingControlMigrationTargetV1>,
    val requiredAcks: List<SharingControlMigrationRequirementV1>,
    val mode: String = "hard-cutover",
)

sealed interface SharingControlEventV1 {
    val eventId: String
    val profileId: String
    val actorKeyId: String
    val sequence: Long
    val createdAt: String
    val signature: String
}

data class SharingControlMemberUpsertEventV1(
    override val eventId: String,
    override val profileId: String,
    override val actorKeyId: String,
    override val sequence: Long,
    override val createdAt: String,
    override val signature: String,
    val member: SharingControlMemberV1,
) : SharingControlEventV1

data class SharingControlMigrationAnnouncedEventV1(
    override val eventId: String,
    override val profileId: String,
    override val actorKeyId: String,
    override val sequence: Long,
    override val createdAt: String,
    override val signature: String,
    val migration: SharingControlMigrationV1,
) : SharingControlEventV1

data class SharingControlMigrationAcknowledgedEventV1(
    override val eventId: String,
    override val profileId: String,
    override val actorKeyId: String,
    override val sequence: Long,
    override val createdAt: String,
    override val signature: String,
    val migrationId: String,
    val openedFileIds: List<String>,
) : SharingControlEventV1

data class SharingControlMigrationClosedEventV1(
    override val eventId: String,
    override val profileId: String,
    override val actorKeyId: String,
    override val sequence: Long,
    override val createdAt: String,
    override val signature: String,
    val migrationId: String,
    val forced: Boolean? = null,
) : SharingControlEventV1

data class SharingControlStateV1(
    val schemaVersion: Int = 1,
    val kind: String = SHARING_CONTROL_KIND,
    val profileId: String,
    val events: List<SharingControlEventV1>,
)

data class VerifiedSharingControlStateV1(
    val state: SharingControlStateV1,
    val ownerKeyId: String,
    val members: Map<String, SharingControlMemberV1>,
    val migrations: Map<String, SharingControlMigrationV1>,
    val acknowledgements: Map<String, Map<String, SharingControlMigrationAcknowledgedEventV1>>,
    val closedMigrations: Set<String>,
)

data class SharingControlMigrationStatusV1(
    val migration: SharingControlMigrationV1,
    val acknowledgedKeyIds: List<String>,
    val pendingKeyIds: List<String>,
    val closed: Boolean,
)

fun createSharingControlCodec(): SharedBackupControllerCodec<SharingControlStateV1> =
    object : SharedBackupControllerCodec<SharingControlStateV1> {
        override fun serialize(value: SharingControlStateV1): JsonElement =
            sharingControlStateToJson(parseSharingControlStateV1(sharingControlStateToJson(value)))

        override fun parse(value: JsonElement): SharingControlStateV1 =
            parseSharingControlStateV1(value)

        override fun merge(
            local: SharingControlStateV1,
            remote: SharingControlStateV1,
        ): SharingControlStateV1 = mergeSharingControlStates(local, remote)

        override fun fingerprint(value: SharingControlStateV1): String =
            CanonicalJson.encode(serialize(value))
    }

fun parseSharingControlStateV1(value: JsonElement): SharingControlStateV1 {
    val state = objectValue(value, "control state")
    exact(state.long("schemaVersion"), 1L, "control state schemaVersion")
    exact(state.string("kind"), SHARING_CONTROL_KIND, "control state kind")
    val profileId = nonEmpty(state.string("profileId"), "control state profileId")
    val events = state.array("events").map(::parseSharingControlEventV1)
    if (events.any { it.profileId != profileId }) compatibility("A control event belongs to another profile.")
    if (events.map { it.eventId }.distinct().size != events.size) compatibility("Duplicate control event.")
    return SharingControlStateV1(profileId = profileId, events = sortControlEvents(events))
}

fun parseSharingControlEventV1(value: JsonElement): SharingControlEventV1 {
    val event = objectValue(value, "control event")
    exact(event.long("schemaVersion"), 1L, "control event schemaVersion")
    exact(event.string("kind"), SHARING_CONTROL_EVENT_KIND, "control event kind")
    val eventId = nonEmpty(event.string("eventId"), "control event eventId")
    val profileId = nonEmpty(event.string("profileId"), "control event profileId")
    val actorKeyId = nonEmpty(event.string("actorKeyId"), "control event actorKeyId")
    val sequence = event.long("sequence")
    if (sequence < 0) compatibility("control event sequence must be a non-negative integer.")
    val createdAt = nonEmpty(event.string("createdAt"), "control event createdAt")
    try { Instant.parse(createdAt) } catch (_: Exception) { compatibility("control event createdAt must be an ISO timestamp.") }
    val signature = nonEmpty(event.string("signature"), "control event signature")
    return when (event.string("type")) {
        "member-upsert" -> SharingControlMemberUpsertEventV1(
            eventId, profileId, actorKeyId, sequence, createdAt, signature,
            parseControlMember(event.required("member")),
        )
        "migration-announced" -> SharingControlMigrationAnnouncedEventV1(
            eventId, profileId, actorKeyId, sequence, createdAt, signature,
            parseControlMigration(event.required("migration")),
        )
        "migration-acknowledged" -> SharingControlMigrationAcknowledgedEventV1(
            eventId, profileId, actorKeyId, sequence, createdAt, signature,
            nonEmpty(event.string("migrationId"), "control acknowledgement migrationId"),
            stringArray(event.required("openedFileIds"), "control acknowledgement openedFileIds"),
        )
        "migration-closed" -> SharingControlMigrationClosedEventV1(
            eventId, profileId, actorKeyId, sequence, createdAt, signature,
            nonEmpty(event.string("migrationId"), "control close migrationId"),
            event.optionalBoolean("forced", "control close forced"),
        )
        else -> compatibility("Unsupported control event type.")
    }
}

fun mergeSharingControlStates(
    local: SharingControlStateV1,
    remote: SharingControlStateV1,
): SharingControlStateV1 {
    val left = parseSharingControlStateV1(sharingControlStateToJson(local))
    val right = parseSharingControlStateV1(sharingControlStateToJson(remote))
    if (left.profileId != right.profileId) compatibility("Cannot merge control states for different profiles.")
    val events = linkedMapOf<String, SharingControlEventV1>()
    for (event in left.events + right.events) {
        val existing = events[event.eventId]
        if (existing != null && canonicalEvent(existing) != canonicalEvent(event)) {
            throw SyncKitError(SyncKitErrorCode.CONFLICT, "Control event ${event.eventId} has conflicting contents.")
        }
        events[event.eventId] = event
    }
    return SharingControlStateV1(profileId = left.profileId, events = sortControlEvents(events.values.toList()))
}

fun verifySharingControlStateV1(
    input: SharingControlStateV1,
    trustedOwnerKeyId: String? = null,
): VerifiedSharingControlStateV1 {
    val state = parseSharingControlStateV1(sharingControlStateToJson(input))
    val members = linkedMapOf<String, SharingControlMemberV1>()
    val migrations = linkedMapOf<String, SharingControlMigrationV1>()
    val acknowledgements = linkedMapOf<String, MutableMap<String, SharingControlMigrationAcknowledgedEventV1>>()
    val closed = linkedSetOf<String>()
    val genesis = state.events.firstOrNull()
    if (genesis !is SharingControlMemberUpsertEventV1 || genesis.sequence != 0L || genesis.actorKeyId != genesis.member.publicKey.keyId) {
        throw SyncKitError(SyncKitErrorCode.AUTHORIZATION, "The first control event must be a self-signed owner member record.")
    }
    val ownerKeyId = genesis.actorKeyId
    if (trustedOwnerKeyId != null && ownerKeyId != trustedOwnerKeyId) {
        throw SyncKitError(SyncKitErrorCode.AUTHORIZATION, "The control ledger owner does not match the pinned dataset owner.")
    }
    for (event in state.events) {
        val actor = members[event.actorKeyId] ?: if (event === genesis) genesis.member else null
            ?: throw SyncKitError(SyncKitErrorCode.AUTHORIZATION, "Control event ${event.eventId} has an unknown actor.")
        verifyControlEvent(event, actor.publicKey)
        when (event) {
            is SharingControlMemberUpsertEventV1 -> {
                ownerOnly(event.actorKeyId, ownerKeyId, "publish membership records")
                members[event.member.publicKey.keyId] = event.member
            }
            is SharingControlMigrationAnnouncedEventV1 -> {
                ownerOnly(event.actorKeyId, ownerKeyId, "announce a migration")
                if (migrations.containsKey(event.migration.migrationId)) {
                    throw SyncKitError(SyncKitErrorCode.CONFLICT, "Migration ${event.migration.migrationId} was announced twice.")
                }
                if (event.migration.requiredAcks.any { !members.containsKey(it.keyId) }) {
                    throw SyncKitError(SyncKitErrorCode.AUTHORIZATION, "Migration ${event.migration.migrationId} requires an unknown member.")
                }
                migrations[event.migration.migrationId] = event.migration
            }
            is SharingControlMigrationAcknowledgedEventV1 -> {
                val migration = migrations[event.migrationId]
                    ?: throw SyncKitError(SyncKitErrorCode.STATE, "Acknowledgement references unknown migration ${event.migrationId}.")
                val requirement = migration.requiredAcks.find { it.keyId == event.actorKeyId }
                    ?: throw SyncKitError(SyncKitErrorCode.AUTHORIZATION, "This member is not required to acknowledge the migration.")
                if (event.migrationId in closed) throw SyncKitError(SyncKitErrorCode.STATE, "A closed migration cannot receive another acknowledgement.")
                requireExactPickerFiles(requirement, event.openedFileIds)
                acknowledgements.getOrPut(event.migrationId) { linkedMapOf() }[event.actorKeyId] = event
            }
            is SharingControlMigrationClosedEventV1 -> {
                val migration = migrations[event.migrationId]
                    ?: throw SyncKitError(SyncKitErrorCode.STATE, "Close references unknown migration ${event.migrationId}.")
                ownerOnly(event.actorKeyId, ownerKeyId, "close a migration")
                val pending = migration.requiredAcks.filter { acknowledgements[event.migrationId]?.containsKey(it.keyId) != true }
                if (pending.isNotEmpty() && event.forced != true) {
                    throw SyncKitError(SyncKitErrorCode.STATE, "A migration cannot close before every required acknowledgement arrives.")
                }
                closed += event.migrationId
            }
        }
    }
    return VerifiedSharingControlStateV1(state, ownerKeyId, members, migrations, acknowledgements, closed)
}

fun missingSharingControlPickerFiles(
    requirement: SharingControlMigrationRequirementV1,
    openedFileIds: Collection<String>,
): List<String> = requirement.targetFileIds.filterNot(openedFileIds.toSet()::contains)

class SharingControlDataset(
    private val controller: SharedBackupController<SharingControlStateV1>,
    private val datasetId: String,
    private val profileId: String,
    private val identity: suspend () -> SharingIdentity,
    private val now: () -> Instant = Instant::now,
    private val randomUuid: () -> String = { UUID.randomUUID().toString() },
    private val maxPublishAttempts: Int = 3,
) {
    init {
        require(datasetId.isNotBlank()) { "control datasetId must not be empty." }
        require(profileId.isNotBlank()) { "control profileId must not be empty." }
    }

    suspend fun create(owner: SharingControlMemberMetadataV1 = SharingControlMemberMetadataV1()): SharedDatasetResult<SharingControlStateV1> {
        val current = identity()
        val member = SharingControlMemberV1(current.publicKey, owner.email, owner.googleSubject, owner.drivePermissionId)
        val event = sign(current, 0, "member-upsert", member = member)
        return controller.createDataset(datasetId, SharingControlStateV1(profileId = profileId, events = listOf(event)))
    }

    suspend fun read(): VerifiedSharingControlStateV1 {
        val trust = controller.getDatasetTrust(datasetId)
        return verifySharingControlStateV1(controller.loadDataset(datasetId).value, trust.trustedOwnerKeyId)
    }

    suspend fun addMember(member: SharingControlMemberV1): SharedDatasetResult<SharingControlStateV1> =
        publish({ current, sequence -> sign(current, sequence, "member-upsert", member = member) }, ::requireOwner)

    suspend fun synchronizeMembers(
        metadata: Map<String, SharingControlMemberMetadataV1> = emptyMap(),
    ): SharedDatasetResult<SharingControlStateV1>? {
        val verified = read()
        requireOwner(verified, identity())
        val participants = controller.getDatasetParticipants(datasetId).participants
        var last: SharedDatasetResult<SharingControlStateV1>? = null
        for (participant in participants) {
            val details = metadata[participant.keyId] ?: SharingControlMemberMetadataV1()
            val member = SharingControlMemberV1(
                participant.toPublicKey(),
                details.email,
                details.googleSubject ?: participant.accepted?.googleSubject,
                details.drivePermissionId ?: participant.accepted?.drivePermissionId,
            )
            if (verified.members[participant.keyId] != member) last = addMember(member)
        }
        return last
    }

    suspend fun announceMigration(migration: SharingControlMigrationV1): SharedDatasetResult<SharingControlStateV1> =
        publish({ current, sequence -> sign(current, sequence, "migration-announced", migration = migration) }, ::requireOwner)

    suspend fun acknowledgeMigration(
        migrationId: String,
        openedFileIds: List<String>,
    ): SharedDatasetResult<SharingControlStateV1> = publish(
        { current, sequence ->
            sign(current, sequence, "migration-acknowledged", migrationId = migrationId, openedFileIds = openedFileIds.distinct().sorted())
        },
        { verified, current ->
            val requirement = verified.migrations[migrationId]?.requiredAcks?.find { it.keyId == current.publicKey.keyId }
                ?: throw SyncKitError(SyncKitErrorCode.AUTHORIZATION, "This identity is not required to acknowledge this migration.")
            requireExactPickerFiles(requirement, openedFileIds)
        },
    )

    suspend fun migrationStatus(migrationId: String): SharingControlMigrationStatusV1 {
        val verified = read()
        val migration = verified.migrations[migrationId]
            ?: throw SyncKitError(SyncKitErrorCode.NOT_FOUND, "Migration $migrationId was not found.")
        val acknowledged = verified.acknowledgements[migrationId].orEmpty().keys.sorted()
        return SharingControlMigrationStatusV1(
            migration,
            acknowledged,
            migration.requiredAcks.filter { it.keyId !in acknowledged }.map { it.keyId },
            migrationId in verified.closedMigrations,
        )
    }

    suspend fun closeMigration(
        migrationId: String,
        force: Boolean = false,
    ): SharedDatasetResult<SharingControlStateV1> = publish(
        { current, sequence -> sign(current, sequence, "migration-closed", migrationId = migrationId, forced = force.takeIf { it }) },
        { verified, current ->
            requireOwner(verified, current)
            val migration = verified.migrations[migrationId]
                ?: throw SyncKitError(SyncKitErrorCode.NOT_FOUND, "Migration $migrationId was not found.")
            val pending = migration.requiredAcks.filter { verified.acknowledgements[migrationId]?.containsKey(it.keyId) != true }
            if (pending.isNotEmpty() && !force) throw SyncKitError(SyncKitErrorCode.STATE, "Migration still awaits: ${pending.joinToString { it.keyId }}.")
        },
    )

    private suspend fun publish(
        build: (SharingIdentity, Long) -> SharingControlEventV1,
        authorize: (VerifiedSharingControlStateV1, SharingIdentity) -> Unit,
    ): SharedDatasetResult<SharingControlStateV1> {
        var lastError: Throwable? = null
        repeat(maxPublishAttempts) { attempt ->
            try {
                val loaded = controller.loadDataset(datasetId)
                val trust = controller.getDatasetTrust(datasetId)
                val verified = verifySharingControlStateV1(loaded.value, trust.trustedOwnerKeyId)
                val current = identity()
                authorize(verified, current)
                val sequence = (loaded.value.events.maxOfOrNull { it.sequence } ?: -1L) + 1L
                val next = loaded.value.copy(events = loaded.value.events + build(current, sequence))
                return controller.syncDataset(datasetId, next)
            } catch (error: Throwable) {
                lastError = error
                if (error !is SyncKitError || error.code != SyncKitErrorCode.CONFLICT || attempt + 1 >= maxPublishAttempts) throw error
            }
        }
        throw lastError ?: IllegalStateException("Control publication failed.")
    }

    private fun sign(
        current: SharingIdentity,
        sequence: Long,
        type: String,
        member: SharingControlMemberV1? = null,
        migration: SharingControlMigrationV1? = null,
        migrationId: String? = null,
        openedFileIds: List<String>? = null,
        forced: Boolean? = null,
    ): SharingControlEventV1 {
        val base = ControlEventBase(randomUuid(), profileId, current.publicKey.keyId, sequence, now().toString())
        val normalized = parseSharingControlEventV1(
            controlEventJson(base, type, member, migration, migrationId, openedFileIds, forced, "unsigned"),
        )
        val unsigned = eventToJson(normalized, includeSignature = false)
        val signature = Base64Url.encode(SharingEcKeys.sign(current.signingPrivateKey, CanonicalJson.encodeAad(unsigned)))
        return parseSharingControlEventV1(JsonObject(unsigned + ("signature" to JsonPrimitive(signature))))
    }

    private fun requireOwner(verified: VerifiedSharingControlStateV1, current: SharingIdentity) {
        if (verified.ownerKeyId != current.publicKey.keyId) {
            throw SyncKitError(SyncKitErrorCode.AUTHORIZATION, "Only the control owner may perform this operation.")
        }
    }
}

private data class ControlEventBase(
    val eventId: String,
    val profileId: String,
    val actorKeyId: String,
    val sequence: Long,
    val createdAt: String,
)

private fun verifyControlEvent(event: SharingControlEventV1, publicKey: SharingPublicKeyV1) {
    val expected = SharingEcKeys.createSharingPublicKeyV1(publicKey.encryptionPublicKey, publicKey.signingPublicKey)
    if (expected.keyId != publicKey.keyId) throw SyncKitError(SyncKitErrorCode.KEY, "Control member ${publicKey.keyId} has an invalid fingerprint.")
    val unsigned = eventToJson(event, includeSignature = false)
    val valid = SharingEcKeys.verify(
        SharingEcKeys.signingPublicKey(publicKey),
        CanonicalJson.encodeAad(unsigned),
        Base64Url.decode(event.signature),
    )
    if (!valid) throw SyncKitError(SyncKitErrorCode.CRYPTO, "Control event ${event.eventId} has an invalid signature.")
}

private fun requireExactPickerFiles(requirement: SharingControlMigrationRequirementV1, opened: Collection<String>) {
    if (missingSharingControlPickerFiles(requirement, opened).isNotEmpty()) {
        throw SyncKitError(SyncKitErrorCode.STATE, "Migration acknowledgement omits one or more required Picker files.")
    }
    if (opened.any { it !in requirement.targetFileIds }) {
        throw SyncKitError(SyncKitErrorCode.STATE, "Migration acknowledgement includes an unexpected Picker file.")
    }
}

private fun ownerOnly(actor: String, owner: String, action: String) {
    if (actor != owner) throw SyncKitError(SyncKitErrorCode.AUTHORIZATION, "Only the control owner may $action.")
}

private fun parseControlMember(value: JsonElement): SharingControlMemberV1 {
    val member = objectValue(value, "control member")
    val publicKey = objectValue(member.required("publicKey"), "control member publicKey")
    return SharingControlMemberV1(
        SharingPublicKeyV1(
            nonEmpty(publicKey.string("keyId"), "control member publicKey keyId"),
            nonEmpty(publicKey.string("encryptionAlgorithm"), "control member publicKey encryptionAlgorithm"),
            nonEmpty(publicKey.string("encryptionPublicKey"), "control member publicKey encryptionPublicKey"),
            nonEmpty(publicKey.string("signatureAlgorithm"), "control member publicKey signatureAlgorithm"),
            nonEmpty(publicKey.string("signingPublicKey"), "control member publicKey signingPublicKey"),
        ),
        member.optionalString("email", "control member email"),
        member.optionalString("googleSubject", "control member googleSubject"),
        member.optionalString("drivePermissionId", "control member drivePermissionId"),
    )
}

private fun parseControlMigration(value: JsonElement): SharingControlMigrationV1 {
    val migration = objectValue(value, "control migration")
    exact(migration.string("mode"), "hard-cutover", "control migration mode")
    val sources = stringArray(migration.required("sourceDatasetIds"), "control sourceDatasetIds")
    val targets = migration.array("targets").map { raw ->
        val target = objectValue(raw, "control migration target")
        SharingControlMigrationTargetV1(
            nonEmpty(target.string("datasetId"), "control target datasetId"),
            nonEmpty(target.string("fileId"), "control target fileId"),
            target.optionalString("revisionId", "control target revisionId"),
        )
    }
    val required = migration.array("requiredAcks").map { raw ->
        val requirement = objectValue(raw, "control acknowledgement requirement")
        SharingControlMigrationRequirementV1(
            nonEmpty(requirement.string("keyId"), "control acknowledgement keyId"),
            stringArray(requirement.required("targetFileIds"), "control acknowledgement targetFileIds"),
        )
    }
    unique(sources, "control source dataset")
    unique(targets.map { it.fileId }, "control target file")
    unique(required.map { it.keyId }, "control acknowledgement member")
    return SharingControlMigrationV1(
        nonEmpty(migration.string("migrationId"), "control migrationId"),
        sources, targets, required,
    )
}

private fun sharingControlStateToJson(state: SharingControlStateV1): JsonObject = buildJsonObject {
    put("schemaVersion", state.schemaVersion)
    put("kind", state.kind)
    put("profileId", state.profileId)
    put("events", buildJsonArray { state.events.forEach { add(eventToJson(it)) } })
}

private fun eventToJson(event: SharingControlEventV1, includeSignature: Boolean = true): JsonObject {
    val base = ControlEventBase(event.eventId, event.profileId, event.actorKeyId, event.sequence, event.createdAt)
    return when (event) {
        is SharingControlMemberUpsertEventV1 -> controlEventJson(base, "member-upsert", member = event.member, signature = event.signature.takeIf { includeSignature })
        is SharingControlMigrationAnnouncedEventV1 -> controlEventJson(base, "migration-announced", migration = event.migration, signature = event.signature.takeIf { includeSignature })
        is SharingControlMigrationAcknowledgedEventV1 -> controlEventJson(base, "migration-acknowledged", migrationId = event.migrationId, openedFileIds = event.openedFileIds, signature = event.signature.takeIf { includeSignature })
        is SharingControlMigrationClosedEventV1 -> controlEventJson(base, "migration-closed", migrationId = event.migrationId, forced = event.forced, signature = event.signature.takeIf { includeSignature })
    }
}

private fun controlEventJson(
    base: ControlEventBase,
    type: String,
    member: SharingControlMemberV1? = null,
    migration: SharingControlMigrationV1? = null,
    migrationId: String? = null,
    openedFileIds: List<String>? = null,
    forced: Boolean? = null,
    signature: String? = null,
): JsonObject = buildJsonObject {
    put("schemaVersion", 1); put("kind", SHARING_CONTROL_EVENT_KIND); put("eventId", base.eventId)
    put("profileId", base.profileId); put("actorKeyId", base.actorKeyId); put("sequence", base.sequence)
    put("createdAt", base.createdAt); put("type", type)
    member?.let { put("member", memberToJson(it)) }
    migration?.let { put("migration", migrationToJson(it)) }
    migrationId?.let { put("migrationId", it) }
    openedFileIds?.let { put("openedFileIds", stringJsonArray(it)) }
    forced?.let { put("forced", it) }
    signature?.let { put("signature", it) }
}

private fun memberToJson(member: SharingControlMemberV1): JsonObject = buildJsonObject {
    put("publicKey", buildJsonObject {
        put("keyId", member.publicKey.keyId); put("encryptionAlgorithm", member.publicKey.encryptionAlgorithm)
        put("encryptionPublicKey", member.publicKey.encryptionPublicKey); put("signatureAlgorithm", member.publicKey.signatureAlgorithm)
        put("signingPublicKey", member.publicKey.signingPublicKey)
    })
    member.email?.let { put("email", it) }; member.googleSubject?.let { put("googleSubject", it) }
    member.drivePermissionId?.let { put("drivePermissionId", it) }
}

private fun migrationToJson(migration: SharingControlMigrationV1): JsonObject = buildJsonObject {
    put("migrationId", migration.migrationId); put("sourceDatasetIds", stringJsonArray(migration.sourceDatasetIds))
    put("targets", buildJsonArray { migration.targets.forEach { target -> add(buildJsonObject {
        put("datasetId", target.datasetId); put("fileId", target.fileId); target.revisionId?.let { put("revisionId", it) }
    }) } })
    put("requiredAcks", buildJsonArray { migration.requiredAcks.forEach { requirement -> add(buildJsonObject {
        put("keyId", requirement.keyId); put("targetFileIds", stringJsonArray(requirement.targetFileIds))
    }) } })
    put("mode", migration.mode)
}

private fun canonicalEvent(event: SharingControlEventV1): String = CanonicalJson.encode(eventToJson(event))
private fun sortControlEvents(events: List<SharingControlEventV1>): List<SharingControlEventV1> =
    events.sortedWith(compareBy<SharingControlEventV1> { it.sequence }.thenBy { it.eventId })
private fun stringJsonArray(values: List<String>): JsonArray = buildJsonArray { values.forEach { add(JsonPrimitive(it)) } }

private fun SharedBackupParticipantV1.toPublicKey() = SharingPublicKeyV1(
    keyId, encryptionAlgorithm, encryptionPublicKey, signatureAlgorithm, signingPublicKey,
)

private fun objectValue(value: JsonElement, name: String): JsonObject =
    value as? JsonObject ?: compatibility("$name must be an object.")
private fun JsonObject.required(key: String): JsonElement = this[key] ?: compatibility("$key is required.")
private fun JsonObject.string(key: String): String = required(key).jsonPrimitive.content
private fun JsonObject.optionalString(key: String, name: String): String? = this[key]?.jsonPrimitive?.contentOrNull?.let { nonEmpty(it, name) }
private fun JsonObject.long(key: String): Long = required(key).jsonPrimitive.long
private fun JsonObject.optionalBoolean(key: String, name: String): Boolean? = this[key]?.let {
    try { it.jsonPrimitive.boolean } catch (_: Exception) { compatibility("$name must be a boolean.") }
}
private fun JsonObject.array(key: String): JsonArray = required(key).jsonArray
private fun stringArray(value: JsonElement, name: String): List<String> {
    val result = value.jsonArray.map { nonEmpty(it.jsonPrimitive.content, name) }
    unique(result, name)
    return result.sorted()
}
private fun unique(values: List<String>, name: String) {
    if (values.distinct().size != values.size) compatibility("$name contains duplicates.")
}
private fun nonEmpty(value: String, name: String): String = value.takeIf { it.isNotBlank() } ?: compatibility("$name must be a non-empty string.")
private fun exact(value: Any, expected: Any, name: String) { if (value != expected) compatibility("$name is unsupported.") }
private fun compatibility(message: String): Nothing = throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, message)
