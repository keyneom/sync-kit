package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

interface SharedBackupControllerCodec<T> : SharedBackupCodec<T> {
    fun merge(local: T, remote: T): T
    fun fingerprint(value: T): String
}

data class SharedDatasetResult<T>(
    val datasetId: String,
    val fileId: String,
    val revisionId: String,
    val value: T,
    val outcome: String,
)

data class DatasetTrust(val trustedOwnerKeyId: String)

data class DatasetParticipants(
    val trustedOwnerKeyId: String,
    val participants: List<SharedBackupParticipantV1>,
)

data class SharingInvitationResult(
    val invitation: SharingInvitationV1,
    val invitationFileId: String,
    val drivePermissionId: String,
)

data class AcceptedDatasetResult(
    val datasetId: String,
    val fileId: String? = null,
    val revisionId: String? = null,
    val permissionId: String? = null,
    val status: String,
    val error: Throwable? = null,
)

data class RotatedDatasetResult(
    val datasetId: String,
    val status: String,
    val revisionId: String? = null,
    val error: Throwable? = null,
)

sealed class DrivePermissionReconciliationAction {
    data class GrantedOrUpdated(
        val kind: String,
        val keyId: String,
        val permissionId: String,
        val role: String,
    ) : DrivePermissionReconciliationAction()

    data class Removed(val permissionId: String) : DrivePermissionReconciliationAction()
    data class Unchanged(val keyId: String) : DrivePermissionReconciliationAction()
    data class Skipped(val keyId: String, val reason: String) : DrivePermissionReconciliationAction()
}

data class DrivePermissionReconciliationResult(
    val datasetId: String,
    val actions: List<DrivePermissionReconciliationAction>,
)

data class InviteParticipantInput(
    val emailAddress: String,
    val requestedGrants: List<SharingDatasetGrantV1>,
    val expiresAt: String? = null,
    val sendNotificationEmail: Boolean? = null,
    val emailMessage: String? = null,
    val joinLandingUrl: String? = null,
    val joinUrl: String? = null,
    val appDisplayName: String? = null,
)

class SharedBackupController<T>(
    private val appId: String,
    private val codec: SharedBackupControllerCodec<T>,
    private val codecForDataset: ((String) -> SharedBackupControllerCodec<*>?)? = null,
    private val identity: suspend () -> SharingIdentity,
    private val transport: SharedBackupTransport,
    private val registry: SharedBackupRegistry,
    private val cryptoOptions: SharingCryptoOptions = SharingCryptoOptions(),
    private val createAccountBinding: (suspend (AccountBindingContext) -> SharingAccountBindingV1)? = null,
    private val verifyAccountBinding: (suspend (SharingAccountBindingV1, VerifiedAccountBindingContext) -> VerifiedAccount)? = null,
    private val requireAccountBinding: Boolean = false,
    private val resolveFork: (suspend (ForkContext<T>) -> String)? = null,
) {
    init {
        require(appId.isNotBlank()) { "appId must not be empty." }
    }

    private val mutex = Mutex()

    suspend fun ensureStorage(): SharedBackupStorage = transport.ensureStorage()

    suspend fun listDatasets(): List<SharedDatasetFile> = transport.listDatasets()

    /** Returns the locally pinned genesis owner for a previously trusted dataset. */
    suspend fun getDatasetTrust(datasetId: String): DatasetTrust {
        val record = requiredRegistry(datasetId)
        return DatasetTrust(record.trustedOwnerKeyId)
    }

    /** Returns verified cryptographic membership, including acceptance provenance. */
    suspend fun getDatasetParticipants(datasetId: String): DatasetParticipants = serialized {
        val stored = readDatasetById(datasetId)
        val record = requiredRegistry(datasetId)
        verifyHead(stored, record)
        DatasetParticipants(record.trustedOwnerKeyId, sharedBackupParticipants(stored.envelope))
    }

    suspend fun createDataset(datasetId: String, value: T): SharedDatasetResult<T> = serialized {
        requireNonEmpty(datasetId, "datasetId")
        if (transport.listDatasets().any { it.datasetId == datasetId }) {
            throw SyncKitError(SyncKitErrorCode.CONFLICT, "Dataset $datasetId already exists.")
        }
        val currentIdentity = identity()
        val selectedCodec = codecFor(datasetId)
        val envelope = SharingCrypto.createSharedBackupEnvelopeV1(
            value = value,
            codec = selectedCodec,
            identity = currentIdentity,
            input = CreateSharedBackupEnvelopeInput(
                appId = appId,
                backupId = datasetId,
                participants = listOf(
                    SharedBackupParticipantInput(
                        publicKey = currentIdentity.publicKey,
                        role = SharingRole.OWNER,
                    ),
                ),
            ),
            options = cryptoOptions,
        )
        val stored = transport.createDataset(datasetId, envelope)
        persistHead(stored, currentIdentity.publicKey.keyId)
        result(stored, value, "created")
    }

    /**
     * Reconnect to an existing dataset this identity can already decrypt —
     * e.g. after a reinstall, or when an interrupted setup left the Drive
     * file without a local registry record. The owner key is pinned from the
     * envelope itself (trust-on-first-use), so callers recovering their own
     * dataset should pass [requireOwned] to insist this identity is the
     * dataset's owner.
     */
    suspend fun adoptDataset(
        datasetId: String,
        requireOwned: Boolean = false,
    ): SharedDatasetResult<T> = serialized {
        val stored = readDatasetById(datasetId)
        val previous = registry.get(datasetId)
        val record = previous ?: initialOwnerRecord(stored)
        SharingCrypto.verifySharedBackupEnvelopeV1(
            stored.envelope,
            VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
        )
        val currentIdentity = identity()
        val selectedCodec = codecFor(datasetId)
        if (requireOwned) {
            val self = sharedBackupParticipant(stored.envelope, currentIdentity.publicKey.keyId)
            if (self == null || self.role != SharingRole.OWNER) {
                throw SyncKitError(
                    SyncKitErrorCode.AUTHORIZATION,
                    "This identity does not own dataset $datasetId.",
                )
            }
        }
        val value = SharingCrypto.decryptSharedBackupEnvelopeV1(
            stored.envelope,
            selectedCodec,
            currentIdentity,
            VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
        )
        persistHead(stored, record.trustedOwnerKeyId, previous)
        result(stored, value, "adopted")
    }

    /** Delete a dataset file from the transport and forget its local record. */
    suspend fun deleteDataset(datasetId: String): Unit = serialized {
        requireNonEmpty(datasetId, "datasetId")
        val fileId = registry.get(datasetId)?.fileId
            ?: transport.listDatasets().find { it.datasetId == datasetId }?.fileId
        if (fileId != null) transport.deleteDataset(fileId)
        registry.delete(datasetId)
    }

    /**
     * Move a dataset file to the provider's trash and forget its local
     * record. The recovery-safe disposal for a topology migration's retired
     * source file: the owner can still restore it during the provider's
     * grace window, but it stops resolving as a live dataset
     * (docs/sharing-control-datasets.md, hard-cutover step 5).
     */
    suspend fun trashDataset(datasetId: String): Unit = serialized {
        requireNonEmpty(datasetId, "datasetId")
        val fileId = registry.get(datasetId)?.fileId
            ?: transport.listDatasets().find { it.datasetId == datasetId }?.fileId
        if (fileId != null) transport.trashDataset(fileId)
        registry.delete(datasetId)
    }

    suspend fun loadDataset(datasetId: String): SharedDatasetResult<T> = serialized {
        val stored = readDatasetById(datasetId)
        val record = requiredRegistry(datasetId)
        verifyHead(stored, record)
        val selectedCodec = codecFor(datasetId)
        val value = SharingCrypto.decryptSharedBackupEnvelopeV1(
            stored.envelope,
            selectedCodec,
            identity(),
            VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
        )
        persistHead(stored, record.trustedOwnerKeyId, record)
        result(stored, value, "loaded")
    }

    suspend fun syncDataset(datasetId: String, localValue: T): SharedDatasetResult<T> = serialized {
        val stored = readDatasetById(datasetId)
        val record = requiredRegistry(datasetId)
        val forked = verifyHead(stored, record, allowFork = true)
        val currentIdentity = identity()
        val selectedCodec = codecFor(datasetId)
        val remoteValue = SharingCrypto.decryptSharedBackupEnvelopeV1(
            stored.envelope,
            selectedCodec,
            currentIdentity,
            VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
        )
        if (forked) {
            val decision = resolveFork?.invoke(
                ForkContext(
                    datasetId = datasetId,
                    lastVerifiedRevisionId = record.lastRevisionId.orEmpty(),
                    remoteRevisionId = stored.envelope.revisionId,
                    localValue = localValue,
                    remoteValue = remoteValue,
                ),
            )
            if (decision != "merge") {
                throw SyncKitError(
                    SyncKitErrorCode.CONFLICT,
                    "Dataset $datasetId has a divergent signed head.",
                )
            }
        }
        val merged = selectedCodec.merge(localValue, remoteValue)
        if (selectedCodec.fingerprint(merged) == selectedCodec.fingerprint(remoteValue)) {
            persistHead(stored, record.trustedOwnerKeyId, record)
            return@serialized result(stored, merged, "unchanged")
        }
        val next = SharingCrypto.createSharedBackupEnvelopeV1(
            value = merged,
            codec = selectedCodec,
            identity = currentIdentity,
            input = CreateSharedBackupEnvelopeInput(
                appId = appId,
                backupId = datasetId,
                participants = participantInputs(stored.envelope),
                previous = stored.envelope,
            ),
            options = cryptoOptions,
        )
        val updated = transport.writeDataset(stored, next)
        persistHead(updated, record.trustedOwnerKeyId, record)
        result(updated, merged, "updated")
    }

    suspend fun inviteParticipant(input: InviteParticipantInput): SharingInvitationResult = serialized {
        val currentIdentity = identity()
        val trustedOwnerKeyIds = mutableSetOf<String>()
        for (grant in input.requestedGrants) {
            val stored = readDatasetById(grant.datasetId)
            val record = requiredRegistry(grant.datasetId)
            SharingCrypto.verifySharedBackupEnvelopeV1(
                stored.envelope,
                VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
            )
            val actor = sharedBackupParticipant(stored.envelope, currentIdentity.publicKey.keyId)
            if (actor == null || !canAdministerSharedBackup(actor.role)) {
                throw SyncKitError(
                    SyncKitErrorCode.AUTHORIZATION,
                    "This identity cannot invite participants to ${grant.datasetId}.",
                )
            }
            trustedOwnerKeyIds += record.trustedOwnerKeyId
        }
        if (trustedOwnerKeyIds.size != 1) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "One invitation cannot combine datasets with different owner trust roots.",
            )
        }
        val trustedOwnerKeyId = trustedOwnerKeyIds.first()
        val storage = transport.ensureStorage()
        val appDisplayName = input.appDisplayName?.trim()?.takeIf { it.isNotEmpty() } ?: appId
        val emailMessage = input.emailMessage ?: when {
            input.joinLandingUrl != null -> formatSharingInviteEmailMessage(
                joinUrl = appendSharingJoinParams(
                    input.joinLandingUrl,
                    SharingJoinParams(appFolderId = storage.appFolderId),
                ),
                appDisplayName = appDisplayName,
            )
            input.joinUrl != null -> formatSharingInviteEmailMessage(
                joinUrl = input.joinUrl,
                appDisplayName = appDisplayName,
            )
            else -> null
        }
        val access = transport.grantExchangeAccess(
            emailAddress = input.emailAddress,
            sendNotificationEmail = input.sendNotificationEmail,
            emailMessage = emailMessage,
        )
        val invitation = SharingCrypto.createSharingInvitationV1(
            identity = currentIdentity,
            input = CreateSharingInvitationInput(
                appId = appId,
                appFolderId = access.appFolderId,
                recipientDrivePermissionId = access.drivePermissionId,
                requestedGrants = input.requestedGrants,
                trustedOwnerKeyId = trustedOwnerKeyId,
                expiresAt = input.expiresAt,
            ),
            options = cryptoOptions,
        )
        SharingInvitationResult(
            invitation = invitation,
            invitationFileId = transport.createInvitation(invitation),
            drivePermissionId = access.drivePermissionId,
        )
    }

    suspend fun listExchanges(
        exchangeId: String? = null,
        kind: String? = null,
    ): List<SharedExchangeFile> = transport.listExchanges(exchangeId, kind)

    suspend fun submitKeyResponse(
        invitationFileId: String,
    ): Pair<String, String> = serialized {
        val invitation = SharingCrypto.verifySharingInvitationV1(
            transport.readInvitation(invitationFileId),
            cryptoOptions,
        )
        val storage = transport.ensureStorage()
        if (invitation.appId != appId || invitation.appFolderId != storage.appFolderId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The invitation belongs to another app storage hierarchy.",
            )
        }
        val currentIdentity = identity()
        val accountBinding = createAccountBinding?.invoke(
            AccountBindingContext(
                appId = appId,
                exchangeId = invitation.exchangeId,
                sharingKeyId = currentIdentity.publicKey.keyId,
            ),
        )
        val response = SharingCrypto.createSharingPublicKeyResponseV1(
            identity = currentIdentity,
            appId = appId,
            exchangeId = invitation.exchangeId,
            options = cryptoOptions,
            accountBinding = accountBinding,
        )
        val datasets = transport.listDatasets()
        for (grant in invitation.requestedGrants) {
            val existing = registry.get(grant.datasetId)
            if (existing != null && existing.trustedOwnerKeyId != invitation.trustedOwnerKeyId) {
                throw SyncKitError(
                    SyncKitErrorCode.CONFLICT,
                    "Dataset ${grant.datasetId} is already pinned to another owner key.",
                )
            }
        }
        for (grant in invitation.requestedGrants) {
            val file = datasets.find { it.datasetId == grant.datasetId }
            val existing = registry.get(grant.datasetId)
            registry.set(
                existing?.copy(fileId = file?.fileId ?: existing.fileId)
                    ?: SharedDatasetRegistryRecord(
                        datasetId = grant.datasetId,
                        fileId = file?.fileId,
                        trustedOwnerKeyId = invitation.trustedOwnerKeyId,
                    ),
            )
        }
        transport.createKeyResponse(response) to invitation.exchangeId
    }

    suspend fun acceptKeyResponse(
        invitation: SharingInvitationV1,
        responseFileId: String,
        recipientEmailAddress: String,
    ): List<AcceptedDatasetResult> = serialized {
        val currentIdentity = identity()
        val responseFile = transport.readKeyResponse(
            responseFileId,
            invitation.recipientDrivePermissionId,
        )
        val binding = responseFile.response.accountBinding
        if (requireAccountBinding && binding == null) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "The key response has no required Google/passkey account binding.",
            )
        }
        val verifiedAccount = if (binding != null && verifyAccountBinding != null) {
            verifyAccountBinding.invoke(
                binding,
                VerifiedAccountBindingContext(
                    appId = appId,
                    exchangeId = invitation.exchangeId,
                    sharingKeyId = responseFile.response.keyId,
                    credentialId = binding.passkey.credentialId,
                ),
            )
        } else {
            null
        }
        if (binding != null && requireAccountBinding && verifyAccountBinding == null) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "Account binding is required but no verifier is configured.",
            )
        }
        val accepted = SharingCrypto.acceptSharingPublicKeyResponseV1(
            invitation = invitation,
            response = responseFile.response,
            acceptedByKeyId = currentIdentity.publicKey.keyId,
            drivePermissionId = responseFile.ownerPermissionId,
            options = cryptoOptions,
            googleSubject = verifiedAccount?.subject,
        )
        if (verifiedAccount != null) {
            transport.deleteExchange(responseFileId)
        }
        applyAcceptedGrants(accepted, currentIdentity, recipientEmailAddress)
    }

    /**
     * Applies verified acceptance grants to each dataset: add the participant,
     * re-encrypt, write, and per-email-share the dataset file. Shared by the
     * Drive-file accept path and the link-payload accept path.
     */
    private suspend fun applyAcceptedGrants(
        accepted: List<AcceptedSharingGrantV1>,
        currentIdentity: SharingIdentity,
        recipientEmailAddress: String,
    ): List<AcceptedDatasetResult> =
        accepted.map { grant ->
            try {
                val stored = readDatasetById(grant.datasetId)
                val selectedCodec = codecFor(grant.datasetId)
                val record = registry.get(grant.datasetId) ?: initialOwnerRecord(stored)
                verifyHead(stored, record)
                val value = SharingCrypto.decryptSharedBackupEnvelopeV1(
                    stored.envelope,
                    selectedCodec,
                    currentIdentity,
                    VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
                )
                val participants = participantInputs(stored.envelope)
                    .filter { it.publicKey.keyId != grant.participant.publicKey.keyId } +
                    grant.participant
                val next = SharingCrypto.createSharedBackupEnvelopeV1(
                    value = value,
                    codec = selectedCodec,
                    identity = currentIdentity,
                    input = CreateSharedBackupEnvelopeInput(
                        appId = appId,
                        backupId = grant.datasetId,
                        participants = participants,
                        previous = stored.envelope,
                    ),
                    options = cryptoOptions,
                )
                val updated = transport.writeDataset(stored, next)
                val permission = transport.setDatasetPermission(
                    fileId = stored.fileId,
                    emailAddress = recipientEmailAddress,
                    role = grant.participant.role,
                    hasInheritedReadAccess = true,
                )
                val participantPermissionIds = buildMap {
                    record.participantPermissionIds?.let { putAll(it) }
                    permission.permissionId?.let {
                        put(grant.participant.publicKey.keyId, it)
                    }
                }
                registry.set(
                    record.copy(
                        fileId = updated.fileId,
                        lastRevisionId = updated.envelope.revisionId,
                        participantPermissionIds = participantPermissionIds,
                    ),
                )
                AcceptedDatasetResult(
                    datasetId = grant.datasetId,
                    fileId = updated.fileId,
                    revisionId = updated.envelope.revisionId,
                    permissionId = permission.permissionId,
                    status = "accepted",
                )
            } catch (error: Throwable) {
                AcceptedDatasetResult(
                    datasetId = grant.datasetId,
                    status = "failed",
                    error = error,
                )
            }
        }

    /**
     * Owner side of the link-carried exchange. Per-email shares each granted
     * dataset file (so it lands in the recipient's Picker) and returns the signed
     * invitation + file list to embed in the join link. Writes no Drive
     * `exchanges/` invitation file.
     */
    suspend fun inviteParticipantForLink(
        emailAddress: String,
        requestedGrants: List<SharingDatasetGrantV1>,
        expiresAt: String? = null,
    ): SharingLinkInvite = serialized {
        val currentIdentity = identity()
        val trustedOwnerKeyIds = mutableSetOf<String>()
        val files = mutableListOf<SharingDatasetFileV1>()
        for (grant in requestedGrants) {
            val stored = readDatasetById(grant.datasetId)
            val record = requiredRegistry(grant.datasetId)
            SharingCrypto.verifySharedBackupEnvelopeV1(
                stored.envelope,
                VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
            )
            val actor = sharedBackupParticipant(stored.envelope, currentIdentity.publicKey.keyId)
            if (actor == null || !canAdministerSharedBackup(actor.role)) {
                throw SyncKitError(
                    SyncKitErrorCode.AUTHORIZATION,
                    "This identity cannot invite participants to ${grant.datasetId}.",
                )
            }
            trustedOwnerKeyIds += record.trustedOwnerKeyId
            transport.setDatasetPermission(
                fileId = stored.fileId,
                emailAddress = emailAddress,
                role = grant.role,
                hasInheritedReadAccess = false,
            )
            files += SharingDatasetFileV1(grant.datasetId, stored.fileId, grant.role)
        }
        if (trustedOwnerKeyIds.size != 1) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "One invitation cannot combine datasets with different owner trust roots.",
            )
        }
        val storage = transport.ensureStorage()
        val invitation = SharingCrypto.createSharingInvitationV1(
            identity = currentIdentity,
            input = CreateSharingInvitationInput(
                appId = appId,
                appFolderId = storage.appFolderId,
                recipientDrivePermissionId = SHARING_LINK_PERMISSION_ID,
                requestedGrants = requestedGrants,
                trustedOwnerKeyId = trustedOwnerKeyIds.first(),
                expiresAt = expiresAt,
            ),
            options = cryptoOptions,
        )
        SharingLinkInvite(invitation, files)
    }

    /**
     * Recipient side. Verifies the invitation carried in the join link, registers
     * the granted datasets with their file ids (so later reads/writes resolve
     * without listing the owner's folder), and returns a signed key response to
     * send back to the owner. Reads/writes no Drive `exchanges/` file.
     */
    suspend fun submitKeyResponseFromInvitation(
        invitation: SharingInvitationV1,
        datasetFiles: List<SharingDatasetFileV1>,
    ): SharingPublicKeyResponseV1 = serialized {
        val verified = SharingCrypto.verifySharingInvitationV1(invitation, cryptoOptions)
        if (verified.appId != appId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The invitation belongs to another app.",
            )
        }
        val currentIdentity = identity()
        val accountBinding = createAccountBinding?.invoke(
            AccountBindingContext(
                appId = appId,
                exchangeId = verified.exchangeId,
                sharingKeyId = currentIdentity.publicKey.keyId,
            ),
        )
        val response = SharingCrypto.createSharingPublicKeyResponseV1(
            identity = currentIdentity,
            appId = appId,
            exchangeId = verified.exchangeId,
            options = cryptoOptions,
            accountBinding = accountBinding,
        )
        val fileById = datasetFiles.associate { it.datasetId to it.fileId }
        for (grant in verified.requestedGrants) {
            val existing = registry.get(grant.datasetId)
            if (existing != null && existing.trustedOwnerKeyId != verified.trustedOwnerKeyId) {
                throw SyncKitError(
                    SyncKitErrorCode.CONFLICT,
                    "Dataset ${grant.datasetId} is already pinned to another owner key.",
                )
            }
            val fileId = fileById[grant.datasetId]
            registry.set(
                existing?.copy(fileId = fileId ?: existing.fileId)
                    ?: SharedDatasetRegistryRecord(
                        datasetId = grant.datasetId,
                        fileId = fileId,
                        trustedOwnerKeyId = verified.trustedOwnerKeyId,
                    ),
            )
        }
        response
    }

    /**
     * Owner side. Accepts a key response carried in a response link (no Drive
     * `exchanges/` read), adds the recipient to each granted dataset, and
     * per-email shares the dataset files. The invitation must be supplied by the
     * caller (persisted at invite time, keyed by exchange id).
     */
    suspend fun acceptKeyResponseFromPayload(
        invitation: SharingInvitationV1,
        response: SharingPublicKeyResponseV1,
        recipientEmailAddress: String,
    ): List<AcceptedDatasetResult> = serialized {
        val currentIdentity = identity()
        val binding = response.accountBinding
        if (requireAccountBinding && binding == null) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "The key response has no required account binding.",
            )
        }
        val verifiedAccount = if (binding != null && verifyAccountBinding != null) {
            verifyAccountBinding.invoke(
                binding,
                VerifiedAccountBindingContext(
                    appId = appId,
                    exchangeId = invitation.exchangeId,
                    sharingKeyId = response.keyId,
                    credentialId = binding.passkey.credentialId,
                ),
            )
        } else {
            null
        }
        val accepted = SharingCrypto.acceptSharingPublicKeyResponseV1(
            invitation = invitation,
            response = response,
            acceptedByKeyId = currentIdentity.publicKey.keyId,
            drivePermissionId = invitation.recipientDrivePermissionId,
            options = cryptoOptions,
            googleSubject = verifiedAccount?.subject,
        )
        applyAcceptedGrants(accepted, currentIdentity, recipientEmailAddress)
    }

    suspend fun reconcileDrivePermissions(
        datasetId: String,
        participantEmails: Map<String, String>,
    ): DrivePermissionReconciliationResult = serialized {
        val stored = readDatasetById(datasetId)
        val record = requiredRegistry(datasetId)
        verifyHead(stored, record)
        val currentIdentity = identity()
        val actor = sharedBackupParticipant(stored.envelope, currentIdentity.publicKey.keyId)
        if (actor == null || !canAdministerSharedBackup(actor.role)) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "Only a current owner or admin can reconcile Drive permissions.",
            )
        }
        val livePermissions = transport.listDatasetPermissions(stored.fileId)
        val directPermissions = livePermissions.filter { !it.inherited }
        val actions = mutableListOf<DrivePermissionReconciliationAction>()
        val expectedPermissionIds = mutableSetOf<String>()
        var participantPermissionIds = record.participantPermissionIds.orEmpty().toMutableMap()
        val participants = sharedBackupParticipants(stored.envelope)
            .filter { it.role != SharingRole.OWNER }
        for (participant in participants) {
            val emailAddress = participantEmails[participant.keyId]?.trim().orEmpty()
            val expectedRole = if (participant.role == SharingRole.VIEWER) "reader" else "writer"
            val permissionId = participantPermissionIds[participant.keyId]
            val live = when {
                permissionId != null -> directPermissions.find { it.permissionId == permissionId }
                emailAddress.isNotEmpty() -> directPermissions.find {
                    it.emailAddress?.lowercase() == emailAddress.lowercase()
                }
                else -> null
            }
            if (
                participant.role == SharingRole.VIEWER &&
                permissionId == null &&
                emailAddress.isEmpty() &&
                livePermissions.any { it.inherited && it.role == "reader" }
            ) {
                actions += DrivePermissionReconciliationAction.Unchanged(participant.keyId)
                continue
            }
            if (emailAddress.isEmpty()) {
                if (live?.role == expectedRole) {
                    expectedPermissionIds += live.permissionId
                    actions += DrivePermissionReconciliationAction.Unchanged(participant.keyId)
                } else {
                    actions += DrivePermissionReconciliationAction.Skipped(
                        participant.keyId,
                        "No email address was provided for reconciliation.",
                    )
                    if (live != null) {
                        expectedPermissionIds += live.permissionId
                    }
                }
                continue
            }
            if (live?.role == expectedRole) {
                expectedPermissionIds += live.permissionId
                if (permissionId != live.permissionId) {
                    participantPermissionIds[participant.keyId] = live.permissionId
                }
                actions += DrivePermissionReconciliationAction.Unchanged(participant.keyId)
                continue
            }
            val permission = transport.setDatasetPermission(
                fileId = stored.fileId,
                emailAddress = emailAddress,
                role = participant.role,
                existingDirectPermissionId = live?.permissionId,
                hasInheritedReadAccess = participant.role == SharingRole.VIEWER,
            )
            val grantedPermissionId = permission.permissionId
            if (grantedPermissionId == null) {
                actions += DrivePermissionReconciliationAction.Unchanged(participant.keyId)
                continue
            }
            expectedPermissionIds += grantedPermissionId
            participantPermissionIds[participant.keyId] = grantedPermissionId
            actions += DrivePermissionReconciliationAction.GrantedOrUpdated(
                kind = if (live != null) "updated" else "granted",
                keyId = participant.keyId,
                permissionId = grantedPermissionId,
                role = permission.role,
            )
        }
        if (participantPermissionIds != record.participantPermissionIds.orEmpty()) {
            registry.set(record.copy(participantPermissionIds = participantPermissionIds))
        }
        val removedPermissionIds = mutableSetOf<String>()
        for (permission in directPermissions) {
            val tracked = participantPermissionIds.values.contains(permission.permissionId)
            if (tracked && permission.permissionId !in expectedPermissionIds) {
                transport.removeDatasetPermission(stored.fileId, permission.permissionId)
                removedPermissionIds += permission.permissionId
                actions += DrivePermissionReconciliationAction.Removed(permission.permissionId)
            }
        }
        if (removedPermissionIds.isNotEmpty()) {
            participantPermissionIds = participantPermissionIds.filterValues {
                it !in removedPermissionIds
            }.toMutableMap()
            registry.set(record.copy(participantPermissionIds = participantPermissionIds))
        }
        DrivePermissionReconciliationResult(datasetId, actions)
    }

    /**
     * Changes one accepted participant's encrypted role and keeps its direct
     * Drive file permission aligned with that role.
     */
    /**
     * Grant a dataset to a participant whose sharing public key this identity
     * already holds — no invitation/response exchange. This is how a topology
     * migration "shares each target with its intended recipients"
     * (docs/sharing-control-datasets.md, hard-cutover step 2), and how an
     * owner adds a dataset to someone who joined before that dataset existed:
     * the content key is wrapped to the participant's existing public key and
     * the file is per-email shared on the transport.
     *
     * Upsert semantics: re-running with the same participant updates their
     * role instead of failing, so interrupted migrations can simply run the
     * grant phase again.
     */
    suspend fun addDatasetParticipant(
        datasetId: String,
        publicKey: SharingPublicKeyV1,
        role: SharingRole,
        emailAddress: String,
    ): SharedDatasetResult<T> = serialized {
        requireNonEmpty(datasetId, "datasetId")
        requireNonEmpty(publicKey.keyId, "participant keyId")
        requireNonEmpty(emailAddress, "emailAddress")
        if (role == SharingRole.OWNER) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "Owner transfer is not supported by sharing v1.",
            )
        }
        val stored = readDatasetById(datasetId)
        val record = requiredRegistry(datasetId)
        verifyHead(stored, record)
        val currentIdentity = identity()
        val selectedCodec = codecFor(datasetId)
        val actor = sharedBackupParticipant(stored.envelope, currentIdentity.publicKey.keyId)
        if (actor == null || !canAdministerSharedBackup(actor.role)) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "Only a current owner or admin can grant dataset access.",
            )
        }
        val value = SharingCrypto.decryptSharedBackupEnvelopeV1(
            stored.envelope,
            selectedCodec,
            currentIdentity,
            VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
        )
        val participants = participantInputs(stored.envelope)
            .filter { it.publicKey.keyId != publicKey.keyId } +
            SharedBackupParticipantInput(publicKey = publicKey, role = role)
        val existingPermission = findDirectDatasetPermission(
            fileId = stored.fileId,
            permissionId = record.participantPermissionIds?.get(publicKey.keyId),
            emailAddress = emailAddress,
        )
        val permission = transport.setDatasetPermission(
            fileId = stored.fileId,
            emailAddress = emailAddress,
            role = role,
            existingDirectPermissionId = existingPermission?.permissionId,
            hasInheritedReadAccess = false,
        )
        val participantPermissionIds = record.participantPermissionIds.orEmpty().toMutableMap()
        if (permission.permissionId != null) {
            participantPermissionIds[publicKey.keyId] = permission.permissionId
        }
        val next = SharingCrypto.createSharedBackupEnvelopeV1(
            value = value,
            codec = selectedCodec,
            identity = currentIdentity,
            input = CreateSharedBackupEnvelopeInput(
                appId = appId,
                backupId = datasetId,
                participants = participants,
                previous = stored.envelope,
            ),
            options = cryptoOptions,
        )
        val updated = transport.writeDataset(stored, next)
        persistHead(
            updated,
            record.trustedOwnerKeyId,
            record.copy(participantPermissionIds = participantPermissionIds),
        )
        result(updated, value, "updated")
    }

    suspend fun setDatasetRole(
        datasetId: String,
        keyId: String,
        role: SharingRole,
        emailAddress: String,
    ): SharedDatasetResult<T> = serialized {
        requireNonEmpty(datasetId, "datasetId")
        requireNonEmpty(keyId, "keyId")
        requireNonEmpty(emailAddress, "emailAddress")
        if (role == SharingRole.OWNER) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "Owner transfer is not supported by sharing v1.",
            )
        }
        val stored = readDatasetById(datasetId)
        val record = requiredRegistry(datasetId)
        verifyHead(stored, record)
        val currentIdentity = identity()
        val selectedCodec = codecFor(datasetId)
        val actor = sharedBackupParticipant(stored.envelope, currentIdentity.publicKey.keyId)
        if (actor == null || !canAdministerSharedBackup(actor.role)) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "Only a current owner or admin can change dataset access.",
            )
        }
        val value = SharingCrypto.decryptSharedBackupEnvelopeV1(
            stored.envelope,
            selectedCodec,
            currentIdentity,
            VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
        )
        val participants = participantInputs(stored.envelope).map { participant ->
            if (participant.publicKey.keyId == keyId) participant.copy(role = role) else participant
        }
        if (participants.none { it.publicKey.keyId == keyId }) {
            throw SyncKitError(
                SyncKitErrorCode.NOT_FOUND,
                "Participant $keyId is not in this dataset.",
            )
        }
        val existingPermission = findDirectDatasetPermission(
            fileId = stored.fileId,
            permissionId = record.participantPermissionIds?.get(keyId),
            emailAddress = emailAddress,
        )
        val permission = transport.setDatasetPermission(
            fileId = stored.fileId,
            emailAddress = emailAddress,
            role = role,
            existingDirectPermissionId = existingPermission?.permissionId,
            hasInheritedReadAccess = role == SharingRole.VIEWER,
        )
        val participantPermissionIds = record.participantPermissionIds.orEmpty().toMutableMap()
        if (permission.permissionId != null) {
            participantPermissionIds[keyId] = permission.permissionId
        } else {
            participantPermissionIds.remove(keyId)
        }
        val next = SharingCrypto.createSharedBackupEnvelopeV1(
            value = value,
            codec = selectedCodec,
            identity = currentIdentity,
            input = CreateSharedBackupEnvelopeInput(
                appId = appId,
                backupId = datasetId,
                participants = participants,
                previous = stored.envelope,
            ),
            options = cryptoOptions,
        )
        val updated = transport.writeDataset(stored, next)
        persistHead(
            updated,
            record.trustedOwnerKeyId,
            record.copy(participantPermissionIds = participantPermissionIds),
        )
        result(updated, value, "updated")
    }

    /**
     * Removes a non-owner participant from new encrypted revisions and removes
     * the tracked direct Drive file permission for that participant.
     */
    suspend fun revokeDatasetKey(
        datasetId: String,
        keyId: String,
        emailAddress: String? = null,
    ): SharedDatasetResult<T> = serialized {
        requireNonEmpty(datasetId, "datasetId")
        requireNonEmpty(keyId, "keyId")
        val stored = readDatasetById(datasetId)
        val record = requiredRegistry(datasetId)
        verifyHead(stored, record)
        val currentIdentity = identity()
        val selectedCodec = codecFor(datasetId)
        val actor = sharedBackupParticipant(stored.envelope, currentIdentity.publicKey.keyId)
        if (actor == null || !canAdministerSharedBackup(actor.role)) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "Only a current owner or admin can change dataset access.",
            )
        }
        val participant = sharedBackupParticipant(stored.envelope, keyId)
        val value = SharingCrypto.decryptSharedBackupEnvelopeV1(
            stored.envelope,
            selectedCodec,
            currentIdentity,
            VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
        )
        if (participant == null) {
            findDirectDatasetPermission(
                fileId = stored.fileId,
                permissionId = record.participantPermissionIds?.get(keyId),
                emailAddress = emailAddress,
            )?.let { permission ->
                transport.removeDatasetPermission(stored.fileId, permission.permissionId)
            }
            registry.set(
                record.copy(
                    participantPermissionIds = record.participantPermissionIds.orEmpty()
                        .filterKeys { it != keyId },
                ),
            )
            return@serialized result(stored, value, "unchanged")
        }
        if (participant.role == SharingRole.OWNER) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "Owner transfer or removal is not supported by sharing v1.",
            )
        }
        findDirectDatasetPermission(
            fileId = stored.fileId,
            permissionId = record.participantPermissionIds?.get(keyId),
            emailAddress = emailAddress,
        )?.let { permission ->
            transport.removeDatasetPermission(stored.fileId, permission.permissionId)
        }
        val participants = participantInputs(stored.envelope).filter {
            it.publicKey.keyId != keyId
        }
        val next = SharingCrypto.createSharedBackupEnvelopeV1(
            value = value,
            codec = selectedCodec,
            identity = currentIdentity,
            input = CreateSharedBackupEnvelopeInput(
                appId = appId,
                backupId = datasetId,
                participants = participants,
                previous = stored.envelope,
            ),
            options = cryptoOptions,
        )
        val updated = transport.writeDataset(stored, next)
        persistHead(
            updated,
            record.trustedOwnerKeyId,
            record.copy(
                participantPermissionIds = record.participantPermissionIds.orEmpty()
                    .filterKeys { it != keyId },
            ),
        )
        result(updated, value, "updated")
    }

    private suspend fun findDirectDatasetPermission(
        fileId: String,
        permissionId: String?,
        emailAddress: String?,
    ): SharedDatasetDrivePermission? {
        val directPermissions = transport.listDatasetPermissions(fileId).filter { !it.inherited }
        if (permissionId != null) {
            directPermissions.find { it.permissionId == permissionId }?.let { return it }
        }
        val normalizedEmail = emailAddress?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
            ?: return null
        return directPermissions.find {
            it.emailAddress?.lowercase() == normalizedEmail
        }
    }

    private suspend fun readDatasetById(datasetId: String): VersionedSharedDataset {
        requireNonEmpty(datasetId, "datasetId")
        val record = registry.get(datasetId)
        val fileId = record?.fileId
            ?: transport.listDatasets().find { it.datasetId == datasetId }?.fileId
            ?: throw SyncKitError(SyncKitErrorCode.NOT_FOUND, "Dataset $datasetId was not found.")
        return transport.readDataset(fileId)
    }

    private suspend fun requiredRegistry(datasetId: String): SharedDatasetRegistryRecord =
        registry.get(datasetId)
            ?: throw SyncKitError(
                SyncKitErrorCode.STATE,
                "Dataset $datasetId has no pinned owner key. Open it from a verified invitation first.",
            )

    private suspend fun verifyHead(
        stored: VersionedSharedDataset,
        record: SharedDatasetRegistryRecord,
        allowFork: Boolean = false,
    ): Boolean {
        SharingCrypto.verifySharedBackupEnvelopeV1(
            stored.envelope,
            VerifySharedBackupOptions(trustedOwnerKeyId = record.trustedOwnerKeyId),
        )
        if (record.lastRevisionId == null) return false
        if (
            stored.envelope.revisionId != record.lastRevisionId &&
            record.seenRevisionIds?.contains(stored.envelope.revisionId) == true
        ) {
            throw SyncKitError(
                SyncKitErrorCode.CONFLICT,
                "Dataset ${stored.datasetId} rolled back to a previously verified revision.",
            )
        }
        if (
            stored.envelope.revisionId == record.lastRevisionId ||
            stored.envelope.parentRevisionId == record.lastRevisionId ||
            stored.envelope.revisionAncestors?.contains(record.lastRevisionId) == true
        ) {
            return false
        }
        if (allowFork) return true
        throw SyncKitError(
            SyncKitErrorCode.CONFLICT,
            "Dataset ${stored.datasetId} has a divergent signed head.",
        )
    }

    private fun initialOwnerRecord(stored: VersionedSharedDataset): SharedDatasetRegistryRecord {
        val owner = sharedBackupParticipants(stored.envelope).find { it.role == SharingRole.OWNER }
            ?: throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, "The dataset has no owner.")
        return SharedDatasetRegistryRecord(
            datasetId = stored.datasetId,
            fileId = stored.fileId,
            trustedOwnerKeyId = owner.keyId,
        )
    }

    private suspend fun persistHead(
        stored: VersionedSharedDataset,
        trustedOwnerKeyId: String,
        previous: SharedDatasetRegistryRecord? = null,
    ): SharedDatasetRegistryRecord {
        val record = SharedDatasetRegistryRecord(
            datasetId = stored.datasetId,
            fileId = stored.fileId,
            trustedOwnerKeyId = trustedOwnerKeyId,
            lastRevisionId = stored.envelope.revisionId,
            seenRevisionIds = buildList {
                previous?.seenRevisionIds?.let { addAll(it) }
                previous?.lastRevisionId?.let { add(it) }
                add(stored.envelope.revisionId)
            }.distinct().takeLast(256),
            participantPermissionIds = previous?.participantPermissionIds,
        )
        registry.set(record)
        return record
    }

    private fun result(
        stored: VersionedSharedDataset,
        value: T,
        outcome: String,
    ): SharedDatasetResult<T> = SharedDatasetResult(
        datasetId = stored.datasetId,
        fileId = stored.fileId,
        revisionId = stored.envelope.revisionId,
        value = value,
        outcome = outcome,
    )

    private suspend fun <R> serialized(block: suspend () -> R): R =
        mutex.withLock { block() }

    @Suppress("UNCHECKED_CAST")
    private fun codecFor(datasetId: String): SharedBackupControllerCodec<T> =
        (codecForDataset?.invoke(datasetId) ?: codec) as SharedBackupControllerCodec<T>

    private fun participantInputs(envelope: SharedBackupEnvelopeV1): List<SharedBackupParticipantInput> =
        sharedBackupParticipants(envelope).map { participant ->
            SharedBackupParticipantInput(
                publicKey = SharingPublicKeyV1(
                    keyId = participant.keyId,
                    encryptionAlgorithm = participant.encryptionAlgorithm,
                    encryptionPublicKey = participant.encryptionPublicKey,
                    signatureAlgorithm = participant.signatureAlgorithm,
                    signingPublicKey = participant.signingPublicKey,
                ),
                role = participant.role,
                accepted = participant.accepted,
            )
        }

    private fun requireNonEmpty(value: String, name: String) {
        if (value.isBlank()) throw IllegalArgumentException("$name must not be empty.")
    }
}

data class AccountBindingContext(
    val appId: String,
    val exchangeId: String,
    val sharingKeyId: String,
)

data class VerifiedAccountBindingContext(
    val appId: String,
    val exchangeId: String,
    val sharingKeyId: String,
    val credentialId: String,
)

data class VerifiedAccount(val subject: String)

data class ForkContext<T>(
    val datasetId: String,
    val lastVerifiedRevisionId: String,
    val remoteRevisionId: String,
    val localValue: T,
    val remoteValue: T,
)
