package com.keyneom.synckit.stores

import com.keyneom.synckit.sharing.checkpoint.SharedDatasetHead
import com.keyneom.synckit.sharing.checkpoint.SharingSyncCheckpoint
import com.keyneom.synckit.sharing.createSharingChangeDetectorFromTransport
import com.keyneom.synckit.sharing.work.SharingSyncWorker
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SyncKitFolderNameTest {
    @Test
    fun buildSyncKitFolderNameSanitizesInvalidCharacters() {
        assertEquals(
            "Demo — Profile",
            buildSyncKitFolderName(
                SyncKitFolderNameInput(
                    appDisplayName = "Demo",
                    profileLabel = "Profile",
                ),
            ),
        )
    }
}

class SharingSyncWorkerLogicTest {
    @Test
    fun workerEncodesDetectionEvents() = runBlocking {
        val transport = FakeSharingTransport()
        val checkpoint = SharingSyncCheckpoint()
        val detector = createSharingChangeDetectorFromTransport(transport)
        val detection = detector.detect(checkpoint)
        val encoded = SharingSyncWorker.encodeEvents(detection.events)
        assertTrue(encoded.contains("pending-key-response"))
        assertTrue(encoded.contains("exchange-1"))
        assertEquals(1, detection.events.size)
    }
}

private class FakeSharingTransport : com.keyneom.synckit.sharing.SharedBackupTransport {
    override suspend fun ensureStorage(): com.keyneom.synckit.sharing.SharedBackupStorage =
        com.keyneom.synckit.sharing.SharedBackupStorage("folder", "exchanges")

    override suspend fun listDatasets(): List<com.keyneom.synckit.sharing.SharedDatasetFile> =
        emptyList()

    override suspend fun readDataset(fileId: String): com.keyneom.synckit.sharing.VersionedSharedDataset =
        error("not used")

    override suspend fun createDataset(
        datasetId: String,
        envelope: com.keyneom.synckit.sharing.SharedBackupEnvelopeV1,
    ): com.keyneom.synckit.sharing.VersionedSharedDataset = error("not used")

    override suspend fun writeDataset(
        current: com.keyneom.synckit.sharing.VersionedSharedDataset,
        envelope: com.keyneom.synckit.sharing.SharedBackupEnvelopeV1,
    ): com.keyneom.synckit.sharing.VersionedSharedDataset = error("not used")

    override suspend fun grantExchangeAccess(
        emailAddress: String,
        sendNotificationEmail: Boolean?,
        emailMessage: String?,
    ): com.keyneom.synckit.sharing.ExchangeAccessResult = error("not used")

    override suspend fun createInvitation(
        invitation: com.keyneom.synckit.sharing.SharingInvitationV1,
    ): String = error("not used")

    override suspend fun createKeyResponse(
        response: com.keyneom.synckit.sharing.SharingPublicKeyResponseV1,
    ): String = error("not used")

    override suspend fun listExchanges(
        exchangeId: String?,
        kind: String?,
    ): List<com.keyneom.synckit.sharing.SharedExchangeFile> = listOf(
        com.keyneom.synckit.sharing.SharedExchangeFile(
            fileId = "response-1",
            exchangeId = "exchange-1",
            kind = "key-response",
        ),
    )

    override suspend fun readInvitation(
        fileId: String,
    ): com.keyneom.synckit.sharing.SharingInvitationV1 = error("not used")

    override suspend fun readKeyResponse(
        fileId: String,
        expectedDrivePermissionId: String,
    ): com.keyneom.synckit.sharing.SharedKeyResponseFile = error("not used")

    override suspend fun deleteExchange(fileId: String) = Unit

    override suspend fun setDatasetPermission(
        fileId: String,
        emailAddress: String,
        role: com.keyneom.synckit.sharing.SharingRole,
        existingDirectPermissionId: String?,
        hasInheritedReadAccess: Boolean,
    ): com.keyneom.synckit.sharing.SharedDatasetPermission = error("not used")

    override suspend fun removeDatasetPermission(fileId: String, permissionId: String) = Unit

    override suspend fun listDatasetPermissions(
        fileId: String,
    ): List<com.keyneom.synckit.sharing.SharedDatasetDrivePermission> = emptyList()

    override suspend fun listDatasetHeads(): List<SharedDatasetHead> = emptyList()
}
