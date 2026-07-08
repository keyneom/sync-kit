package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.CanonicalJson
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.crypto.V1KeyMetadata
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec

const val PROTECTED_SHARING_IDENTITY_KIND = "sync-kit-protected-sharing-identity"

/**
 * Passkey-wrapped sharing identity, byte-compatible with the web
 * `ProtectedSharingIdentityV1` (src/sharing/web-passkey.ts). Only the
 * AES-GCM-encrypted PKCS#8 private key material is persisted; runtime EC keys
 * are re-imported after every unlock. Hosting this record in `drive.appdata`
 * lets one Google account carry a single sharing identity across its devices.
 */
@Serializable
data class ProtectedSharingIdentityV1(
    val schemaVersion: Int,
    val kind: String,
    val appId: String,
    val rpId: String,
    val credentialId: String,
    val credentialPublicKey: JsonObject? = null,
    val prfInput: String,
    val kdfSalt: String,
    val nonce: String,
    val publicKey: SharingPublicKeyV1,
    val encryptedPrivateKeys: String,
)

/** Identity plus the record that persists it, returned from a wrap. */
data class ProtectedSharingIdentityResult(
    val identity: SharingIdentity,
    val record: ProtectedSharingIdentityV1,
)

object ProtectedSharingIdentityCrypto {
    private val keyFactory: KeyFactory by lazy { KeyFactory.getInstance("EC") }

    /**
     * Wraps a sharing identity for the passkey behind [wrappingKey]. Generates a
     * fresh identity when [identity] is null; passing an existing identity is how
     * a device promotes its legacy device-local keypair into app-data without
     * regenerating it. [wrappingKey] is the 32-byte content key derived from the
     * passkey PRF secret and [metadata].kdfSalt via the sharing V1 profile.
     */
    fun create(
        appId: String,
        metadata: V1KeyMetadata,
        wrappingKey: ByteArray,
        identity: SharingIdentity? = null,
        nonce: ByteArray = randomBytes(12),
        credentialPublicKey: JsonObject? = null,
    ): ProtectedSharingIdentityResult {
        require(appId.isNotBlank()) { "appId must not be empty." }
        require(nonce.size == 12) { "AES-GCM nonce must be 12 bytes." }
        val resolved = identity ?: SharingEcKeys.generateIdentity()
        val packed = packPrivateKeys(
            resolved.encryptionPrivateKey.encoded,
            resolved.signingPrivateKey.encoded,
        )
        try {
            val header = headerJson(
                appId = appId,
                rpId = metadata.rpId,
                credentialId = metadata.credentialId,
                credentialPublicKey = credentialPublicKey,
                prfInput = Base64Url.encode(metadata.prfInput),
                kdfSalt = Base64Url.encode(metadata.kdfSalt),
                nonce = Base64Url.encode(nonce),
                publicKey = resolved.publicKey,
            )
            val ciphertext = SharingEcKeys.encryptAesGcm(
                wrappingKey,
                nonce,
                CanonicalJson.encodeAad(header),
                packed,
            )
            val record = ProtectedSharingIdentityV1(
                schemaVersion = 1,
                kind = PROTECTED_SHARING_IDENTITY_KIND,
                appId = appId,
                rpId = metadata.rpId,
                credentialId = metadata.credentialId,
                credentialPublicKey = credentialPublicKey,
                prfInput = Base64Url.encode(metadata.prfInput),
                kdfSalt = Base64Url.encode(metadata.kdfSalt),
                nonce = Base64Url.encode(nonce),
                publicKey = resolved.publicKey,
                encryptedPrivateKeys = Base64Url.encode(ciphertext),
            )
            return ProtectedSharingIdentityResult(resolved, record)
        } finally {
            packed.fill(0)
        }
    }

    /** Unwraps [record] with the passkey-derived [wrappingKey]. */
    fun unlock(
        record: ProtectedSharingIdentityV1,
        wrappingKey: ByteArray,
    ): SharingIdentity {
        val header = headerJson(
            appId = record.appId,
            rpId = record.rpId,
            credentialId = record.credentialId,
            credentialPublicKey = record.credentialPublicKey,
            prfInput = record.prfInput,
            kdfSalt = record.kdfSalt,
            nonce = record.nonce,
            publicKey = record.publicKey,
        )
        val packed = try {
            SharingEcKeys.decryptAesGcm(
                wrappingKey,
                Base64Url.decode(record.nonce),
                CanonicalJson.encodeAad(header),
                Base64Url.decode(record.encryptedPrivateKeys),
            )
        } catch (error: Exception) {
            throw SyncKitError(
                SyncKitErrorCode.KEY,
                "The passkey could not unlock the protected sharing identity.",
                error,
            )
        }
        try {
            return importIdentity(record, packed)
        } finally {
            packed.fill(0)
        }
    }

    fun parse(json: String): ProtectedSharingIdentityV1 =
        parse(SyncKitJson.instance.decodeFromString(ProtectedSharingIdentityV1.serializer(), json))

    fun parse(record: ProtectedSharingIdentityV1): ProtectedSharingIdentityV1 {
        if (record.schemaVersion != 1 || record.kind != PROTECTED_SHARING_IDENTITY_KIND) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The protected sharing identity version is unsupported.",
            )
        }
        for ((label, value) in listOf(
            "appId" to record.appId,
            "rpId" to record.rpId,
            "credentialId" to record.credentialId,
            "prfInput" to record.prfInput,
            "kdfSalt" to record.kdfSalt,
            "nonce" to record.nonce,
            "encryptedPrivateKeys" to record.encryptedPrivateKeys,
        )) {
            if (value.isBlank()) {
                throw SyncKitError(
                    SyncKitErrorCode.COMPATIBILITY,
                    "$label must be a non-empty string.",
                )
            }
        }
        if (
            Base64Url.decode(record.prfInput).size != 32 ||
            Base64Url.decode(record.kdfSalt).size != 32 ||
            Base64Url.decode(record.nonce).size != 12
        ) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "Protected sharing identity cryptographic metadata is malformed.",
            )
        }
        return record
    }

    private fun importIdentity(
        record: ProtectedSharingIdentityV1,
        packed: ByteArray,
    ): SharingIdentity {
        val (encryptionPrivate, signingPrivate) = unpackPrivateKeys(packed)
        try {
            val identity = SharingIdentity(
                publicKey = record.publicKey,
                encryptionPrivateKey = importPrivateKey(encryptionPrivate),
                signingPrivateKey = importPrivateKey(signingPrivate),
            )
            val expected = SharingEcKeys.createSharingPublicKeyV1(
                record.publicKey.encryptionPublicKey,
                record.publicKey.signingPublicKey,
            )
            if (expected.keyId != record.publicKey.keyId) {
                throw SyncKitError(
                    SyncKitErrorCode.KEY,
                    "The protected sharing identity public-key fingerprint is invalid.",
                )
            }
            return identity
        } finally {
            encryptionPrivate.fill(0)
            signingPrivate.fill(0)
        }
    }

    private fun importPrivateKey(pkcs8: ByteArray): ECPrivateKey =
        keyFactory.generatePrivate(PKCS8EncodedKeySpec(pkcs8)) as ECPrivateKey

    /** Header used as AES-GCM additional data: the record without its ciphertext. */
    private fun headerJson(
        appId: String,
        rpId: String,
        credentialId: String,
        credentialPublicKey: JsonObject?,
        prfInput: String,
        kdfSalt: String,
        nonce: String,
        publicKey: SharingPublicKeyV1,
    ): JsonObject = buildJsonObject {
        put("schemaVersion", 1)
        put("kind", PROTECTED_SHARING_IDENTITY_KIND)
        put("appId", appId)
        put("rpId", rpId)
        put("credentialId", credentialId)
        if (credentialPublicKey != null) put("credentialPublicKey", credentialPublicKey)
        put("prfInput", prfInput)
        put("kdfSalt", kdfSalt)
        put("nonce", nonce)
        put(
            "publicKey",
            buildJsonObject {
                put("keyId", publicKey.keyId)
                put("encryptionAlgorithm", publicKey.encryptionAlgorithm)
                put("encryptionPublicKey", publicKey.encryptionPublicKey)
                put("signatureAlgorithm", publicKey.signatureAlgorithm)
                put("signingPublicKey", publicKey.signingPublicKey)
            },
        )
    }

    /** `[4-byte big-endian length of enc][enc PKCS#8][sig PKCS#8]` (matches TS). */
    private fun packPrivateKeys(enc: ByteArray, sig: ByteArray): ByteArray {
        val packed = ByteArray(4 + enc.size + sig.size)
        packed[0] = (enc.size ushr 24).toByte()
        packed[1] = (enc.size ushr 16).toByte()
        packed[2] = (enc.size ushr 8).toByte()
        packed[3] = enc.size.toByte()
        System.arraycopy(enc, 0, packed, 4, enc.size)
        System.arraycopy(sig, 0, packed, 4 + enc.size, sig.size)
        return packed
    }

    private fun unpackPrivateKeys(packed: ByteArray): Pair<ByteArray, ByteArray> {
        if (packed.size < 5) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "Protected sharing private-key material is malformed.",
            )
        }
        val encLength =
            ((packed[0].toInt() and 0xff) shl 24) or
                ((packed[1].toInt() and 0xff) shl 16) or
                ((packed[2].toInt() and 0xff) shl 8) or
                (packed[3].toInt() and 0xff)
        if (encLength == 0 || 4 + encLength >= packed.size) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "Protected sharing private-key material is malformed.",
            )
        }
        return packed.copyOfRange(4, 4 + encLength) to
            packed.copyOfRange(4 + encLength, packed.size)
    }

    private fun randomBytes(length: Int): ByteArray =
        ByteArray(length).also { java.security.SecureRandom().nextBytes(it) }
}
