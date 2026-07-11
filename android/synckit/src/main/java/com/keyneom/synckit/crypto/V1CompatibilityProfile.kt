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
    val readVersions: List<Int> = listOf(1),
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
    }
}

data class V1KeyMetadata @JvmOverloads constructor(
    val credentialId: String,
    val rpId: String,
    val prfInput: ByteArray,
    val kdfSalt: ByteArray,
    val credentialPublicKey: JsonObject? = null,
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
