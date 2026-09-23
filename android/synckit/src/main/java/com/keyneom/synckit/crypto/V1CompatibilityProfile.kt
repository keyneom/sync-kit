package com.keyneom.synckit.crypto

import kotlinx.serialization.json.JsonObject

const val V1_ALGORITHM = "AES-256-GCM+HKDF-SHA-256"

enum class V1Compression {
    NONE,
    GZIP_IF_SMALLER,
}

data class PasskeyProfile(
    val rpName: String,
    val userName: String,
    val userDisplayName: String,
    val algorithm: Int = -7,
    val residentKey: String = "required",
    val userVerification: String = "required",
    val timeoutMs: Long = 60_000,
)

data class V1CompatibilityProfile(
    val appId: String,
    val filename: String,
    val aad: String,
    val hkdfInfo: String,
    val compression: V1Compression,
    val passkey: PasskeyProfile,
    val algorithm: String = V1_ALGORITHM,
    /**
     * Snapshot versions this app reads; must include 1. Add 2 once every
     * device runs a sync-kit that reads v2 — the first step of a staged rollout.
     */
    val readVersions: List<Int> = listOf(1),
    /**
     * The version a new snapshot is written in; must be one of [readVersions].
     * An existing snapshot changes version only through an explicit
     * `migrateVersion` or `setRecoveryCode`. See docs/snapshot-recovery.md.
     */
    val writeVersion: Int = 1,
    val nonceBytes: Int = 12,
    val kdfSaltBytes: Int = 32,
    val prfInputBytes: Int = 32,
    val tagBits: Int = 128,
) {
    init {
        require(appId.isNotBlank()) { "appId must not be empty." }
        require(filename.isNotBlank()) { "filename must not be empty." }
        require(aad.isNotBlank()) { "aad must not be empty." }
        require(hkdfInfo.isNotBlank()) { "hkdfInfo must not be empty." }
        require(passkey.rpName.isNotBlank()) { "passkey.rpName must not be empty." }
        require(passkey.userName.isNotBlank()) { "passkey.userName must not be empty." }
        require(passkey.userDisplayName.isNotBlank()) {
            "passkey.userDisplayName must not be empty."
        }
        require(passkey.timeoutMs > 0) { "passkey.timeoutMs must be positive." }
        require(1 in readVersions) { "readVersions must include 1: v1 snapshots stay readable indefinitely." }
        require(readVersions.all { it == 1 || it == 2 }) { "readVersions may contain only 1 and 2." }
        require(writeVersion in readVersions) { "writeVersion must be one of readVersions." }
    }
}

/** The locks a v2 snapshot carries, preserved unchanged by ordinary sync. */
data class SnapshotLocksV2(
    val appId: String,
    val contentSalt: String,
    val passkeyKey: SnapshotWrappedKeyV2,
    val recoveryKey: SnapshotRecoveryKeyV2? = null,
)

data class V1KeyMetadata @JvmOverloads constructor(
    val credentialId: String,
    val rpId: String,
    val prfInput: ByteArray,
    val kdfSalt: ByteArray,
    val credentialPublicKey: JsonObject? = null,
    /** Present for a v2 snapshot, so ordinary sync keeps its locks unchanged. */
    val locks: SnapshotLocksV2? = null,
) {
    fun identity(): String =
        "$rpId\n$credentialId\n${Base64Url.encode(kdfSalt)}\n${Base64Url.encode(prfInput)}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is V1KeyMetadata) return false
        return credentialId == other.credentialId &&
            rpId == other.rpId &&
            prfInput.contentEquals(other.prfInput) &&
            kdfSalt.contentEquals(other.kdfSalt)
    }

    override fun hashCode(): Int {
        var result = credentialId.hashCode()
        result = 31 * result + rpId.hashCode()
        result = 31 * result + prfInput.contentHashCode()
        result = 31 * result + kdfSalt.contentHashCode()
        return result
    }
}
