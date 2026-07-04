package com.keyneom.synckit.crypto

import kotlinx.serialization.Serializable

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
) {
    fun metadata(): V1KeyMetadata =
        V1KeyMetadata(
            credentialId = credentialId,
            rpId = rpId,
            prfInput = Base64Url.decode(prfInput),
            kdfSalt = Base64Url.decode(kdfSalt),
        )
}
