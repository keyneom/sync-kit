package com.keyneom.synckit.crypto

import kotlinx.serialization.Serializable

/** The content key, wrapped under one lock of a v2 snapshot. */
@Serializable
data class SnapshotWrappedKeyV2(
    val nonce: String,
    val wrappedKey: String,
)

/** The content key, wrapped under a key derived from a recovery code. */
@Serializable
data class SnapshotRecoveryKeyV2(
    val kdfSalt: String,
    val nonce: String,
    val wrappedKey: String,
)

/**
 * An encrypted private snapshot. `schemaVersion` 1 is the original format and
 * is unchanged. `schemaVersion` 2 adds an explicit [appId], an authenticated
 * header, and a content key held by locks — the passkey and optionally a
 * recovery code — in the fields marked v2. It is read only by profiles listing
 * 2 in `readVersions`. The passkey fields sit in the same place in both, so
 * existing key providers unlock either. See docs/snapshot-recovery.md.
 */
@Serializable
data class SyncEnvelopeV1(
    val schemaVersion: Int = 1,
    val algorithm: String = V1_ALGORITHM,
    /** Null means uncompressed, preserving compatibility with original v1 snapshots. */
    val compression: String? = null,
    val credentialId: String,
    val rpId: String,
    val prfInput: String,
    val kdfSalt: String,
    val nonce: String,
    val ciphertext: String,
    val updatedAt: String,
    /** v2 only. */
    val appId: String? = null,
    /** v2 only. */
    val contentSalt: String? = null,
    /** v2 only: the content key, wrapped under the passkey's derived key. */
    val passkeyKey: SnapshotWrappedKeyV2? = null,
    /** v2 only: the content key, wrapped under a recovery code. */
    val recoveryKey: SnapshotRecoveryKeyV2? = null,
) {
    fun metadata(): V1KeyMetadata =
        V1KeyMetadata(
            credentialId = credentialId,
            rpId = rpId,
            prfInput = Base64Url.decode(prfInput),
            kdfSalt = Base64Url.decode(kdfSalt),
            locks = locks(),
        )

    /** A v2 snapshot's locks, which ordinary sync carries forward unchanged. */
    fun locks(): SnapshotLocksV2? =
        if (schemaVersion != 2 || appId == null || contentSalt == null || passkeyKey == null) {
            null
        } else {
            SnapshotLocksV2(appId, contentSalt, passkeyKey, recoveryKey)
        }
}
