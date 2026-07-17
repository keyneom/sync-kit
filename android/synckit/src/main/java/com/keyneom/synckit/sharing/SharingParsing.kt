package com.keyneom.synckit.sharing

import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode

internal object SharingParsing {
    fun parseSharingPublicKeyResponseV1(value: SharingPublicKeyResponseV1): SharingPublicKeyResponseV1 {
        assertExact(value.schemaVersion, 1, "schemaVersion")
        assertExact(value.kind, SHARING_KEY_KIND, "kind")
        assertNonEmpty(value.appId, "appId")
        assertNonEmpty(value.exchangeId, "exchangeId")
        assertNonEmpty(value.createdAt, "createdAt")
        assertNonEmpty(value.keyId, "keyId")
        assertNonEmpty(value.encryptionPublicKey, "encryptionPublicKey")
        assertNonEmpty(value.signingPublicKey, "signingPublicKey")
        assertNonEmpty(value.proof, "proof")
        assertExact(value.encryptionAlgorithm, SHARING_ENCRYPTION_ALGORITHM, "encryptionAlgorithm")
        assertExact(value.signatureAlgorithm, SHARING_SIGNATURE_ALGORITHM, "signatureAlgorithm")
        validatePublicKey(value.encryptionPublicKey, "encryptionPublicKey")
        validatePublicKey(value.signingPublicKey, "signingPublicKey")
        validateBytes(value.keyId, 32, "keyId")
        validateBytes(value.proof, 64, "proof")
        validateTimestamp(value.createdAt, "createdAt")
        return value
    }

    fun parseSharingInvitationV1(value: SharingInvitationV1): SharingInvitationV1 {
        assertExact(value.schemaVersion, 1, "schemaVersion")
        assertExact(value.kind, SHARING_INVITATION_KIND, "kind")
        assertNonEmpty(value.appId, "appId")
        assertNonEmpty(value.appFolderId, "appFolderId")
        assertNonEmpty(value.exchangeId, "exchangeId")
        assertNonEmpty(value.recipientDrivePermissionId, "recipientDrivePermissionId")
        assertNonEmpty(value.trustedOwnerKeyId, "trustedOwnerKeyId")
        assertNonEmpty(value.createdAt, "createdAt")
        assertNonEmpty(value.signature, "signature")
        validateBytes(value.trustedOwnerKeyId, 32, "trustedOwnerKeyId")
        value.expiresAt?.let {
            if (it.isBlank()) throw compatibility("expiresAt must be a non-empty string.")
            validateTimestamp(it, "expiresAt")
        }
        if (value.requestedGrants.isEmpty()) {
            throw compatibility("requestedGrants must not be empty.")
        }
        val datasetIds = mutableSetOf<String>()
        for (grant in value.requestedGrants) {
            assertNonEmpty(grant.datasetId, "datasetId")
            if (grant.role == SharingRole.OWNER) {
                throw compatibility("An invitation has an unsupported requested role.")
            }
            if (!datasetIds.add(grant.datasetId)) {
                throw compatibility("Duplicate requested dataset ${grant.datasetId}.")
            }
        }
        validateOwnerPublicKey(value.owner)
        validateBytes(value.signature, 64, "signature")
        validateTimestamp(value.createdAt, "createdAt")
        return value
    }

    fun parseSharedBackupEnvelopeV1(value: SharedBackupEnvelopeV1): SharedBackupEnvelopeV1 {
        assertExact(value.schemaVersion, 1, "schemaVersion")
        assertExact(value.kind, SHARED_BACKUP_KIND, "kind")
        assertExact(value.algorithm, SHARING_CONTENT_ALGORITHM, "algorithm")
        assertNonEmpty(value.appId, "appId")
        assertNonEmpty(value.backupId, "backupId")
        assertNonEmpty(value.revisionId, "revisionId")
        assertNonEmpty(value.createdAt, "createdAt")
        assertNonEmpty(value.authorKeyId, "authorKeyId")
        assertNonEmpty(value.payloadNonce, "payloadNonce")
        assertNonEmpty(value.ciphertext, "ciphertext")
        assertNonEmpty(value.signature, "signature")
        value.parentRevisionId?.let {
            if (it.isBlank()) throw compatibility("parentRevisionId must be a non-empty string.")
        }
        value.revisionAncestors?.let { ancestors ->
            if (ancestors.any { it.isBlank() }) {
                throw compatibility("revisionAncestors must contain revision IDs.")
            }
            if (ancestors.size > SHARED_BACKUP_MAX_REVISION_ANCESTORS) {
                throw compatibility(
                    "revisionAncestors must contain at most $SHARED_BACKUP_MAX_REVISION_ANCESTORS revision IDs.",
                )
            }
            if (ancestors.distinct().size != ancestors.size || ancestors.contains(value.revisionId)) {
                throw compatibility("revisionAncestors contains a duplicate or cycle.")
            }
            if (value.parentRevisionId != null && ancestors.lastOrNull() != value.parentRevisionId) {
                throw compatibility("parentRevisionId must be the last revision ancestor.")
            }
            if (value.parentRevisionId == null && ancestors.isNotEmpty()) {
                throw compatibility("A genesis revision cannot have ancestors.")
            }
        }
        if (value.accessControl.isEmpty()) throw compatibility("accessControl must not be empty.")
        if (value.keyGrants.isEmpty()) throw compatibility("keyGrants must not be empty.")
        value.accessControl.forEachIndexed { index, entry -> parseAccessEntry(entry, index) }
        val participants = value.accessControl.last().participants
        val participantIds = participants.map { it.keyId }.toSet()
        if (!participantIds.contains(value.authorKeyId)) {
            throw compatibility("The revision author is not a participant.")
        }
        val grantIds = mutableSetOf<String>()
        for (grant in value.keyGrants) {
            assertNonEmpty(grant.recipientKeyId, "recipientKeyId")
            assertNonEmpty(grant.ephemeralPublicKey, "ephemeralPublicKey")
            assertNonEmpty(grant.kdfSalt, "kdfSalt")
            assertNonEmpty(grant.nonce, "nonce")
            assertNonEmpty(grant.wrappedContentKey, "wrappedContentKey")
            if (!participantIds.contains(grant.recipientKeyId)) {
                throw compatibility("A key grant references a non-participant.")
            }
            if (!grantIds.add(grant.recipientKeyId)) {
                throw compatibility("Duplicate key grant for ${grant.recipientKeyId}.")
            }
            validatePublicKey(grant.ephemeralPublicKey, "ephemeralPublicKey")
            validateBytes(grant.kdfSalt, 32, "kdfSalt")
            validateBytes(grant.nonce, 12, "key-grant nonce")
            Base64Url.decode(grant.wrappedContentKey)
        }
        if (grantIds.size != participantIds.size) {
            throw compatibility("Every participant must have exactly one key grant.")
        }
        validateBytes(value.payloadNonce, 12, "payload nonce")
        Base64Url.decode(value.ciphertext)
        validateBytes(value.signature, 64, "signature")
        validateTimestamp(value.createdAt, "createdAt")
        return value
    }

    private fun parseAccessEntry(entry: SharedBackupAccessV1, index: Int) {
        if (entry.sequence != index) {
            throw compatibility("Access-control sequence is invalid.")
        }
        assertNonEmpty(entry.authorKeyId, "authorKeyId")
        assertNonEmpty(entry.signature, "signature")
        if (entry.appId != null || entry.backupId != null) {
            assertNonEmpty(entry.appId.orEmpty(), "appId")
            assertNonEmpty(entry.backupId.orEmpty(), "backupId")
        }
        validateBytes(entry.authorKeyId, 32, "access author keyId")
        validateBytes(entry.signature, 64, "access signature")
        if (index == 0) {
            if (entry.previousHash != null) {
                throw compatibility("The first access-control entry cannot have a previousHash.")
            }
        } else if (entry.previousHash.isNullOrBlank()) {
            throw compatibility("An access-control entry is missing previousHash.")
        } else {
            validateBytes(entry.previousHash, 32, "access previousHash")
        }
        if (entry.participants.isEmpty()) {
            throw compatibility("Access-control participants must not be empty.")
        }
        val participantIds = mutableSetOf<String>()
        var ownerCount = 0
        for (participant in entry.participants) {
            assertNonEmpty(participant.keyId, "keyId")
            assertNonEmpty(participant.encryptionPublicKey, "encryptionPublicKey")
            assertNonEmpty(participant.signingPublicKey, "signingPublicKey")
            assertExact(participant.encryptionAlgorithm, SHARING_ENCRYPTION_ALGORITHM, "encryptionAlgorithm")
            assertExact(participant.signatureAlgorithm, SHARING_SIGNATURE_ALGORITHM, "signatureAlgorithm")
            validatePublicKey(participant.encryptionPublicKey, "encryptionPublicKey")
            validatePublicKey(participant.signingPublicKey, "signingPublicKey")
            validateBytes(participant.keyId, 32, "participant keyId")
            if (!participantIds.add(participant.keyId)) {
                throw compatibility("Duplicate participant ${participant.keyId}.")
            }
            if (participant.role == SharingRole.OWNER) ownerCount++
        }
        if (ownerCount != 1) {
            throw compatibility("An access-control entry must have exactly one owner.")
        }
        entry.keyRotation?.let { rotation ->
            assertNonEmpty(rotation.fromKeyId, "fromKeyId")
            assertNonEmpty(rotation.toKeyId, "toKeyId")
            assertNonEmpty(rotation.newKeyProof, "newKeyProof")
            validateBytes(rotation.fromKeyId, 32, "fromKeyId")
            validateBytes(rotation.toKeyId, 32, "toKeyId")
            validateBytes(rotation.newKeyProof, 64, "newKeyProof")
        }
        entry.ownershipTransfer?.let { transfer ->
            parseSharedBackupOwnershipTransferV1(transfer, requireAccepted = true)
            if (entry.keyRotation != null) {
                throw compatibility(
                    "An access-control entry cannot rotate a key and transfer ownership.",
                )
            }
        }
    }

    fun parseSharedBackupOwnershipTransferV1(
        value: SharedBackupOwnershipTransferV1,
        requireAccepted: Boolean = false,
    ): SharedBackupOwnershipTransferV1 {
        assertExact(value.schemaVersion, 1, "ownership transfer schemaVersion")
        assertExact(value.kind, SHARING_OWNERSHIP_TRANSFER_KIND, "ownership transfer kind")
        assertNonEmpty(value.transferId, "transferId")
        assertNonEmpty(value.appId, "appId")
        validateBytes(value.fromKeyId, 32, "transfer fromKeyId")
        validateBytes(value.toKeyId, 32, "transfer toKeyId")
        if (value.fromKeyId == value.toKeyId) {
            throw compatibility("An ownership transfer must change the owner key.")
        }
        if (value.previousOwnerRole != SharingRole.ADMIN &&
            value.previousOwnerRole != SharingRole.WRITER
        ) {
            throw compatibility("previousOwnerRole must be admin or writer.")
        }
        if (value.datasets.isEmpty()) {
            throw compatibility("An ownership transfer must include datasets.")
        }
        var priorDatasetId: String? = null
        value.datasets.forEach { dataset ->
            assertNonEmpty(dataset.datasetId, "datasetId")
            assertNonEmpty(dataset.revisionId, "revisionId")
            validateBytes(dataset.accessControlHash, 32, "transfer accessControlHash")
            assertNonEmpty(dataset.providerPermissionId, "providerPermissionId")
            if (priorDatasetId != null &&
                com.keyneom.synckit.crypto.CanonicalJson.compareUtf16CodeUnits(
                    priorDatasetId!!,
                    dataset.datasetId,
                ) >= 0
            ) {
                throw compatibility(
                    "Ownership-transfer datasets must be unique and canonically ordered.",
                )
            }
            priorDatasetId = dataset.datasetId
        }
        if (value.providerObjects.size != 2) {
            throw compatibility(
                "An ownership transfer must include the app and exchanges folders.",
            )
        }
        val expectedProviderKinds = listOf("app-folder", "exchanges-folder")
        val providerFileIds = mutableSetOf<String>()
        value.providerObjects.forEachIndexed { index, providerObject ->
            assertExact(providerObject.kind, expectedProviderKinds[index], "provider object kind")
            assertNonEmpty(providerObject.fileId, "provider object fileId")
            assertNonEmpty(providerObject.providerPermissionId, "providerPermissionId")
            if (!providerFileIds.add(providerObject.fileId)) {
                throw compatibility("Ownership-transfer provider file IDs must be unique.")
            }
        }
        validateTimestamp(value.createdAt, "createdAt")
        value.expiresAt?.let {
            if (it.isBlank()) throw compatibility("expiresAt must be a non-empty string.")
            validateTimestamp(it, "expiresAt")
        }
        validateBytes(value.ownerProof, 64, "ownerProof")
        value.newOwnerProof?.let { validateBytes(it, 64, "newOwnerProof") }
            ?: if (requireAccepted) {
                throw compatibility("The ownership transfer has not been accepted.")
            } else Unit
        return value
    }

    private fun validateOwnerPublicKey(owner: SharingPublicKeyV1) {
        assertNonEmpty(owner.keyId, "keyId")
        assertNonEmpty(owner.encryptionPublicKey, "encryptionPublicKey")
        assertNonEmpty(owner.signingPublicKey, "signingPublicKey")
        assertExact(owner.encryptionAlgorithm, SHARING_ENCRYPTION_ALGORITHM, "encryptionAlgorithm")
        assertExact(owner.signatureAlgorithm, SHARING_SIGNATURE_ALGORITHM, "signatureAlgorithm")
        validatePublicKey(owner.encryptionPublicKey, "encryptionPublicKey")
        validatePublicKey(owner.signingPublicKey, "signingPublicKey")
        validateBytes(owner.keyId, 32, "owner keyId")
    }

    private fun validatePublicKey(value: String, label: String) {
        val bytes = Base64Url.decode(value)
        if (bytes.size != 65 || bytes[0] != 4.toByte()) {
            throw compatibility("$label must be an uncompressed P-256 public key.")
        }
    }

    private fun validateBytes(value: String, expected: Int, label: String) {
        if (Base64Url.decode(value).size != expected) {
            throw compatibility("The $label has an invalid length.")
        }
    }

    private fun validateTimestamp(value: String, label: String) {
        try {
            java.time.Instant.parse(value)
        } catch (_: Exception) {
            throw compatibility("$label must be an ISO-8601 timestamp.")
        }
    }

    private fun assertExact(actual: Any?, expected: Any, label: String) {
        if (actual != expected) {
            throw compatibility("$label must be $expected.")
        }
    }

    private fun assertNonEmpty(value: String, label: String) {
        if (value.isBlank()) throw compatibility("$label must not be empty.")
    }

    private fun compatibility(message: String): SyncKitError =
        SyncKitError(SyncKitErrorCode.COMPATIBILITY, message)
}
