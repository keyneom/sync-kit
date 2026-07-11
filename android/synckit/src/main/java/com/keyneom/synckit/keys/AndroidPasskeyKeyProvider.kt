package com.keyneom.synckit.keys

import android.app.Activity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import com.keyneom.synckit.core.CreatedKey
import com.keyneom.synckit.core.KeyProvider
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.SyncEnvelopeV1
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.crypto.V1CompatibilityProfile
import com.keyneom.synckit.crypto.V1EnvelopeCrypto
import com.keyneom.synckit.crypto.V1KeyMetadata
import kotlinx.coroutines.CompletableDeferred
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * WebAuthn PRF passkey provider backed by Android Credential Manager.
 * Caches only the derived content key in process memory and coalesces
 * concurrent unlocks for the same envelope identity (matching the web provider).
 */
open class AndroidPasskeyKeyProvider<T> @JvmOverloads constructor(
    private val profile: V1CompatibilityProfile,
    private val rpId: String,
    private val envelopeCrypto: V1EnvelopeCrypto<T>,
    private val registrationOrigins: Set<String> = emptySet(),
) : KeyProvider {
    private var cachedIdentity: String? = null
    private var cachedKey: ByteArray? = null
    private var pending: PendingUnlock? = null

    override suspend fun create(activity: Activity, appId: String): CreatedKey {
        val prfInput = envelopeCrypto.randomBytes(profile.prfInputBytes)
        val kdfSalt = envelopeCrypto.randomBytes(profile.kdfSaltBytes)
        val challenge = Base64Url.encode(envelopeCrypto.randomBytes(32))
        val request = createRequest(prfInput, challenge)
        val response = CredentialManager.create(activity).createCredential(
            context = activity,
            request = CreatePublicKeyCredentialRequest(request.toString()),
        ) as? CreatePublicKeyCredentialResponse
            ?: throw SyncKitError(
                SyncKitErrorCode.KEY,
                "Passkey creation did not return a public-key credential.",
            )
        val parsed = SyncKitJson.instance.parseToJsonElement(response.registrationResponseJson).jsonObject
        val credentialId = parsed.string("rawId") ?: parsed.string("id")
            ?: throw SyncKitError(
                SyncKitErrorCode.KEY,
                "Passkey creation did not return a credential id.",
            )
        val secret = prfResultFromResponse(parsed)
            ?: unlockPrf(activity, credentialId, Base64Url.encode(prfInput))
        return try {
            val credentialPublicKey = if (registrationOrigins.isEmpty()) {
                null
            } else {
                extractEs256CredentialPublicKey(
                    response.registrationResponseJson,
                    challenge,
                    rpId,
                    registrationOrigins,
                )
            }
            val metadata = V1KeyMetadata(
                credentialId,
                rpId,
                prfInput,
                kdfSalt,
                credentialPublicKey,
            )
            val key = envelopeCrypto.deriveContentKey(secret, kdfSalt)
            try {
                remember(metadata, key)
                CreatedKey(metadata, key.copyOf())
            } finally {
                key.fill(0)
            }
        } finally {
            secret.fill(0)
        }
    }

    override suspend fun unlock(activity: Activity, envelope: SyncEnvelopeV1): ByteArray {
        if (envelope.rpId != rpId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The protected key belongs to ${envelope.rpId}, not $rpId.",
            )
        }
        val metadata = envelope.metadata()
        getCached(metadata)?.let { return it }

        val identity = metadata.identity()
        val joinOrStart = synchronized(this) {
            getCachedLocked(metadata)?.let { return@synchronized UnlockCacheHit(it) }
            pending?.let { existing ->
                if (existing.identity == identity) {
                    return@synchronized UnlockJoin(existing.deferred)
                }
            }
            val created = CompletableDeferred<ByteArray>()
            pending = PendingUnlock(identity, created)
            UnlockStart(created)
        }

        when (joinOrStart) {
            is UnlockCacheHit -> return joinOrStart.key
            is UnlockJoin -> return joinOrStart.deferred.await().copyOf()
            is UnlockStart -> {
                val ownedDeferred = joinOrStart.deferred
                try {
                    val secret = unlockPrf(activity, envelope.credentialId, envelope.prfInput)
                    val key = try {
                        envelopeCrypto.deriveContentKey(secret, metadata.kdfSalt)
                    } finally {
                        secret.fill(0)
                    }
                    try {
                        remember(metadata, key)
                        val copy = key.copyOf()
                        ownedDeferred.complete(copy)
                        return copy.copyOf()
                    } finally {
                        key.fill(0)
                    }
                } catch (error: Throwable) {
                    ownedDeferred.completeExceptionally(error)
                    throw error
                } finally {
                    synchronized(this) {
                        if (pending?.deferred === ownedDeferred) pending = null
                    }
                }
            }
        }
    }

    /**
     * Derives the content/wrapping key for [metadata] directly, prompting the
     * passkey each call. Used to unwrap a passkey-protected sharing identity,
     * whose key material is cached by the consumer (not here) so this stays off
     * the personal-sync caching/coalescing path.
     */
    suspend fun unlockMetadata(activity: Activity, metadata: V1KeyMetadata): ByteArray {
        if (metadata.rpId != rpId) {
            throw SyncKitError(
                SyncKitErrorCode.COMPATIBILITY,
                "The protected key belongs to ${metadata.rpId}, not $rpId.",
            )
        }
        val secret = unlockPrf(activity, metadata.credentialId, Base64Url.encode(metadata.prfInput))
        return try {
            envelopeCrypto.deriveContentKey(secret, metadata.kdfSalt)
        } finally {
            secret.fill(0)
        }
    }

    override fun clear() {
        synchronized(this) {
            clearLocked()
            pending = null
        }
    }

    fun isUnlockedFor(envelope: SyncEnvelopeV1): Boolean =
        synchronized(this) {
            cachedIdentity == envelope.metadata().identity() && cachedKey != null
        }

    private fun getCached(metadata: V1KeyMetadata): ByteArray? =
        synchronized(this) { getCachedLocked(metadata) }

    private fun getCachedLocked(metadata: V1KeyMetadata): ByteArray? {
        if (cachedIdentity != metadata.identity()) {
            clearLocked()
            return null
        }
        return cachedKey?.copyOf()
    }

    private fun remember(metadata: V1KeyMetadata, key: ByteArray) {
        synchronized(this) {
            clearLocked()
            cachedIdentity = metadata.identity()
            cachedKey = key.copyOf()
        }
    }

    private fun clearLocked() {
        cachedKey?.fill(0)
        cachedKey = null
        cachedIdentity = null
    }

    protected open suspend fun unlockPrf(
        activity: Activity,
        credentialId: String,
        prfInput: String,
    ): ByteArray {
        val option = GetPublicKeyCredentialOption(getRequest(credentialId, prfInput).toString())
        val response = CredentialManager.create(activity).getCredential(
            context = activity,
            request = GetCredentialRequest.Builder().addCredentialOption(option).build(),
        )
        val credential = response.credential as? PublicKeyCredential
            ?: throw SyncKitError(
                SyncKitErrorCode.KEY,
                "Passkey selection did not return a public-key credential.",
            )
        val parsed =
            SyncKitJson.instance.parseToJsonElement(credential.authenticationResponseJson).jsonObject
        return prfResultFromResponse(parsed)
            ?: throw SyncKitError(
                SyncKitErrorCode.KEY,
                "This passkey provider did not return a PRF secret. Try current Google Password Manager and Chrome.",
            )
    }

    private fun createRequest(prfInput: ByteArray, challenge: String): JsonObject = buildJsonObject {
        put("rp", buildJsonObject {
            put("id", rpId)
            put("name", profile.passkey.rpName)
        })
        put("user", buildJsonObject {
            put("id", Base64Url.encode(envelopeCrypto.randomBytes(32)))
            put("name", profile.passkey.userName)
            put("displayName", profile.passkey.userDisplayName)
        })
        put("challenge", challenge)
        put("pubKeyCredParams", buildJsonArray {
            add(buildJsonObject {
                put("type", "public-key")
                put("alg", profile.passkey.algorithm)
            })
        })
        put("authenticatorSelection", buildJsonObject {
            put("residentKey", profile.passkey.residentKey)
            put("requireResidentKey", true)
            put("userVerification", profile.passkey.userVerification)
        })
        put("timeout", profile.passkey.timeoutMs)
        put("attestation", "none")
        put("extensions", prfExtensions(Base64Url.encode(prfInput)))
    }

    private fun getRequest(credentialId: String, prfInput: String): JsonObject = buildJsonObject {
        put("challenge", Base64Url.encode(envelopeCrypto.randomBytes(32)))
        put("rpId", rpId)
        put("allowCredentials", buildJsonArray {
            add(buildJsonObject {
                put("type", "public-key")
                put("id", credentialId)
            })
        })
        put("userVerification", profile.passkey.userVerification)
        put("timeout", profile.passkey.timeoutMs)
        put("extensions", prfExtensions(prfInput))
    }

    companion object {
        internal fun prfResultFromResponse(response: JsonObject): ByteArray? {
            val value = runCatching {
                val prf = response["clientExtensionResults"]!!.jsonObject["prf"]!!.jsonObject
                prf["results"]!!.jsonObject["first"]!!.jsonPrimitive.content
            }.getOrNull() ?: return null
            return Base64Url.decode(value)
        }

        internal fun prfExtensions(prfInput: String): JsonObject = buildJsonObject {
            put("prf", buildJsonObject {
                put("eval", buildJsonObject { put("first", prfInput) })
            })
        }
    }

    private fun JsonObject.string(key: String): String? =
        this[key]?.jsonPrimitive?.content?.takeIf(String::isNotBlank)

    private data class PendingUnlock(
        val identity: String,
        val deferred: CompletableDeferred<ByteArray>,
    )

    private sealed interface UnlockDecision
    private data class UnlockCacheHit(val key: ByteArray) : UnlockDecision
    private data class UnlockJoin(val deferred: CompletableDeferred<ByteArray>) : UnlockDecision
    private data class UnlockStart(val deferred: CompletableDeferred<ByteArray>) : UnlockDecision
}
