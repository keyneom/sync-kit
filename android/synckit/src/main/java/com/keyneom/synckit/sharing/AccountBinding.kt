package com.keyneom.synckit.sharing

import android.app.Activity
import android.os.Build
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.CanonicalJson
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec

const val SHARING_ACCOUNT_BINDING_KIND = "sync-kit-sharing-account-binding"
private const val GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
private val defaultGoogleJwksProvider by lazy { CachingGoogleJwksProvider() }

data class SharingAccountBindingContext(
    val appId: String,
    val exchangeId: String,
    val sharingKeyId: String,
    val credentialId: String,
)

data class SharingAccountBindingCredential(
    val credentialId: String,
    val credentialPublicKey: JsonObject,
)

data class VerifiedGoogleAccount(
    val subject: String,
    val audience: String,
    val email: String? = null,
)

data class GoogleJwksResponse(
    val keys: List<JsonObject>,
    val maxAgeSeconds: Long = 300,
)

fun interface GoogleJwksFetcher {
    suspend fun fetch(): GoogleJwksResponse
}

class CachingGoogleJwksProvider(
    private val fetcher: GoogleJwksFetcher = GoogleJwksFetcher { fetchGoogleJwks() },
    private val nowMillis: () -> Long = System::currentTimeMillis,
) {
    private val mutex = Mutex()
    private var keys: List<JsonObject> = emptyList()
    private var expiresAt = 0L

    suspend fun key(kid: String): JsonObject? {
        var current = load(false)
        current.firstOrNull { it.string("kid") == kid }?.let { return it }
        current = load(true)
        return current.firstOrNull { it.string("kid") == kid }
    }

    suspend fun clear() = mutex.withLock {
        keys = emptyList()
        expiresAt = 0L
    }

    private suspend fun load(force: Boolean): List<JsonObject> = mutex.withLock {
        val now = nowMillis()
        if (!force && keys.isNotEmpty() && now < expiresAt) return@withLock keys
        val response = fetcher.fetch()
        if (response.keys.isEmpty()) compatibility("The Google signing-key response is empty.")
        keys = response.keys
        val ttl = response.maxAgeSeconds.coerceIn(0, 24 * 60 * 60)
        expiresAt = now + ttl * 1_000
        keys
    }
}

object SharingAccountBindings {
    fun createChallenge(context: SharingAccountBindingContext): String {
        requireContext(context)
        val canonical = buildJsonObject {
            put("appId", context.appId)
            put("exchangeId", context.exchangeId)
            put("sharingKeyId", context.sharingKeyId)
            put("credentialId", context.credentialId)
        }
        return Base64Url.encode(
            MessageDigest.getInstance("SHA-256").digest(CanonicalJson.encodeAad(canonical)),
        )
    }

    fun createV1(
        challenge: String,
        googleIdToken: String,
        passkey: SharingPasskeyAssertionV1,
    ): SharingAccountBindingV1 {
        require(Base64Url.decode(challenge).size == 32) { "challenge must be a SHA-256 value." }
        require(googleIdToken.isNotBlank()) { "googleIdToken must not be empty." }
        return SharingAccountBindingV1(1, SHARING_ACCOUNT_BINDING_KIND, challenge, googleIdToken, passkey)
    }

    suspend fun createBackendless(
        activity: Activity,
        context: AccountBindingContext,
        credential: SharingAccountBindingCredential,
        rpId: String,
        requestGoogleIdToken: suspend (nonce: String) -> String,
        timeoutMs: Long = 60_000,
        credentialManager: CredentialManager? = null,
    ): SharingAccountBindingV1 {
        if (Build.VERSION.SDK_INT < 28) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "Credential Manager passkeys require Android 9 (API 28) or newer.",
            )
        }
        val fullContext = SharingAccountBindingContext(
            context.appId,
            context.exchangeId,
            context.sharingKeyId,
            credential.credentialId,
        )
        val challenge = createChallenge(fullContext)
        val requestJson = buildJsonObject {
            put("challenge", challenge)
            put("rpId", rpId)
            put("allowCredentials", buildJsonArray {
                add(buildJsonObject {
                    put("type", "public-key")
                    put("id", credential.credentialId)
                })
            })
            put("userVerification", "required")
            put("timeout", timeoutMs)
        }
        val response = try {
            (credentialManager ?: CredentialManager.create(activity)).getCredential(
                context = activity,
                request = GetCredentialRequest.Builder()
                    .addCredentialOption(GetPublicKeyCredentialOption(requestJson.toString()))
                    .build(),
            )
        } catch (error: GetCredentialCancellationException) {
            throw SyncKitError(SyncKitErrorCode.KEY, "The passkey assertion was cancelled.", error)
        } catch (error: GetCredentialException) {
            throw SyncKitError(SyncKitErrorCode.KEY, "The passkey assertion failed.", error)
        }
        val publicKeyCredential = response.credential as? PublicKeyCredential
            ?: throw SyncKitError(SyncKitErrorCode.KEY, "Passkey selection did not return a public-key credential.")
        val parsed = parseObject(publicKeyCredential.authenticationResponseJson, "WebAuthn assertion")
        val returnedId = parsed.string("rawId") ?: parsed.string("id")
            ?: compatibility("The WebAuthn assertion has no credential id.")
        if (returnedId != credential.credentialId) authorization("The selected passkey is not the protected sharing credential.")
        val responseObject = parsed.objectValue("response")
        val assertion = SharingPasskeyAssertionV1(
            credentialId = returnedId,
            credentialPublicKey = credential.credentialPublicKey,
            authenticatorData = responseObject.requiredString("authenticatorData"),
            clientDataJSON = responseObject.requiredString("clientDataJSON"),
            signature = responseObject.requiredString("signature"),
        )
        return createV1(challenge, requestGoogleIdToken(challenge), assertion)
    }

    suspend fun verify(
        binding: SharingAccountBindingV1,
        context: SharingAccountBindingContext,
        googleAudience: String,
        rpId: String,
        allowedOrigins: Set<String>,
        jwks: CachingGoogleJwksProvider = defaultGoogleJwksProvider,
        requireUserVerification: Boolean = true,
        nowMillis: () -> Long = System::currentTimeMillis,
        clockSkewSeconds: Long = 60,
    ): VerifiedGoogleAccount {
        if (binding.schemaVersion != 1 || binding.kind != SHARING_ACCOUNT_BINDING_KIND) {
            compatibility("The sharing account binding version is unsupported.")
        }
        val expected = createChallenge(context)
        if (binding.challenge != expected || binding.passkey.credentialId != context.credentialId) {
            authorization("The account binding does not match this exchange and sharing key.")
        }
        verifyPasskey(binding.passkey, expected, rpId, allowedOrigins, requireUserVerification)
        return verifyGoogleIdToken(
            binding.googleIdToken,
            googleAudience,
            expected,
            jwks,
            nowMillis,
            clockSkewSeconds,
        )
    }

    fun verifyPasskey(
        assertion: SharingPasskeyAssertionV1,
        challenge: String,
        rpId: String,
        allowedOrigins: Set<String>,
        requireUserVerification: Boolean = true,
    ) {
        val clientBytes = Base64Url.decode(assertion.clientDataJSON)
        val client = parseObject(clientBytes.toString(Charsets.UTF_8), "WebAuthn client data")
        if (
            client.string("type") != "webauthn.get" ||
            client.string("challenge") != challenge ||
            client.string("origin") !in allowedOrigins
        ) authorization("The WebAuthn assertion context is invalid.")
        val authenticatorData = Base64Url.decode(assertion.authenticatorData)
        if (authenticatorData.size < 37) compatibility("The WebAuthn authenticator data is truncated.")
        val expectedRpHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        if (!MessageDigest.isEqual(authenticatorData.copyOfRange(0, 32), expectedRpHash)) {
            authorization("The WebAuthn assertion belongs to another relying party.")
        }
        val flags = authenticatorData[32].toInt() and 0xff
        if (flags and 0x01 == 0) authorization("The WebAuthn assertion lacks user presence.")
        if (requireUserVerification && flags and 0x04 == 0) {
            authorization("The WebAuthn assertion lacks user verification.")
        }
        val signed = authenticatorData + MessageDigest.getInstance("SHA-256").digest(clientBytes)
        val key = parseP256Jwk(assertion.credentialPublicKey)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(key)
        verifier.update(signed)
        val valid = runCatching { verifier.verify(Base64Url.decode(assertion.signature)) }.getOrDefault(false)
        if (!valid) authorization("The WebAuthn assertion signature is invalid.")
    }

    suspend fun verifyGoogleIdToken(
        token: String,
        audience: String,
        nonce: String,
        jwks: CachingGoogleJwksProvider,
        nowMillis: () -> Long = System::currentTimeMillis,
        clockSkewSeconds: Long = 60,
    ): VerifiedGoogleAccount {
        require(clockSkewSeconds >= 0) { "clockSkewSeconds must not be negative." }
        val parts = token.split('.')
        if (parts.size != 3 || parts.any(String::isBlank)) compatibility("The Google ID token is not a complete JWT.")
        val header = parseObject(Base64Url.decode(parts[0]).toString(Charsets.UTF_8), "Google ID token header")
        val claims = parseObject(Base64Url.decode(parts[1]).toString(Charsets.UTF_8), "Google ID token claims")
        val kid = header.string("kid")
        if (header.string("alg") != "RS256" || kid == null) compatibility("The Google ID token algorithm is unsupported.")
        val jwk = jwks.key(kid) ?: authorization("The Google ID token signing key is unknown.")
        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(parseRsaJwk(jwk))
        verifier.update("${parts[0]}.${parts[1]}".toByteArray(Charsets.UTF_8))
        val signatureValid = runCatching { verifier.verify(Base64Url.decode(parts[2])) }.getOrDefault(false)
        if (!signatureValid) authorization("The Google ID token signature is invalid.")

        val now = nowMillis() / 1_000
        val issuer = claims.string("iss")
        val audiences = claims.audiences()
        val expiration = claims.long("exp")
        val issuedAt = claims.long("iat")
        val azp = claims.string("azp")
        if (
            issuer !in setOf("https://accounts.google.com", "accounts.google.com") ||
            audience !in audiences || expiration == null || expiration <= now - clockSkewSeconds ||
            issuedAt == null || issuedAt > now + clockSkewSeconds ||
            (audiences.size > 1 && azp != audience) || (azp != null && azp != audience) ||
            claims.string("nonce") != nonce || claims.string("sub").isNullOrBlank()
        ) authorization("The Google ID token claims do not match this account binding.")
        val email = claims.string("email")
        if (email != null && claims["email_verified"]?.jsonPrimitive?.content != "true") {
            authorization("The Google ID token email is not verified.")
        }
        return VerifiedGoogleAccount(claims.string("sub")!!, audience, email)
    }
}

fun androidApkKeyHashOrigin(certificateBytes: ByteArray): String =
    androidApkKeyHashOriginFromSha256(MessageDigest.getInstance("SHA-256").digest(certificateBytes))

fun androidApkKeyHashOriginFromSha256(fingerprint: ByteArray): String {
    require(fingerprint.size == 32) { "A SHA-256 certificate fingerprint must be 32 bytes." }
    return "android:apk-key-hash:${Base64Url.encode(fingerprint)}"
}

fun androidApkKeyHashOriginFromHexSha256(fingerprint: String): String {
    val normalized = fingerprint.replace(":", "").trim()
    require(normalized.length == 64 && normalized.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
        "A SHA-256 certificate fingerprint must contain 64 hexadecimal characters."
    }
    return androidApkKeyHashOriginFromSha256(
        ByteArray(32) { index -> normalized.substring(index * 2, index * 2 + 2).toInt(16).toByte() },
    )
}

private suspend fun fetchGoogleJwks(): GoogleJwksResponse = withContext(Dispatchers.IO) {
    val connection = URL(GOOGLE_JWKS_URL).openConnection() as HttpURLConnection
    try {
        connection.connectTimeout = 10_000
        connection.readTimeout = 10_000
        val status = connection.responseCode
        if (status !in 200..299) throw SyncKitError(SyncKitErrorCode.NETWORK, "Google signing keys could not be loaded ($status).")
        val root = parseObject(connection.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }, "Google signing-key response")
        val keys = root["keys"]?.jsonArray?.map { it.jsonObject }
            ?: compatibility("The Google signing-key response is malformed.")
        val maxAge = connection.getHeaderField("Cache-Control")
            ?.let { Regex("(?:^|,)\\s*max-age=(\\d+)", RegexOption.IGNORE_CASE).find(it)?.groupValues?.get(1) }
            ?.toLongOrNull() ?: 300
        GoogleJwksResponse(keys, maxAge)
    } finally {
        connection.disconnect()
    }
}

private fun parseP256Jwk(jwk: JsonObject): java.security.PublicKey {
    if (
        jwk.string("kty") != "EC" || jwk.string("crv") != "P-256" ||
        (jwk.string("alg") != null && jwk.string("alg") != "ES256")
    ) {
        compatibility("The passkey public key must be an ES256 P-256 JWK.")
    }
    val x = jwk.string("x")?.let(Base64Url::decode)
        ?: compatibility("The passkey public key has no x coordinate.")
    val y = jwk.string("y")?.let(Base64Url::decode)
        ?: compatibility("The passkey public key has no y coordinate.")
    if (x.size != 32 || y.size != 32) compatibility("The passkey public key coordinates are malformed.")
    val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
        .getParameterSpec(java.security.spec.ECParameterSpec::class.java)
    return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, x), BigInteger(1, y)), parameters))
}

private fun parseRsaJwk(jwk: JsonObject): java.security.PublicKey {
    if (
        jwk.string("kty") != "RSA" ||
        (jwk.string("alg") != null && jwk.string("alg") != "RS256") ||
        (jwk.string("use") != null && jwk.string("use") != "sig")
    ) compatibility("The Google signing key is not an RS256 verification key.")
    val modulus = jwk.string("n")?.let(Base64Url::decode) ?: compatibility("The Google signing key has no modulus.")
    val exponent = jwk.string("e")?.let(Base64Url::decode) ?: compatibility("The Google signing key has no exponent.")
    return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(BigInteger(1, modulus), BigInteger(1, exponent)))
}

private fun requireContext(context: SharingAccountBindingContext) {
    require(context.appId.isNotBlank()) { "appId must not be empty." }
    require(context.exchangeId.isNotBlank()) { "exchangeId must not be empty." }
    require(context.sharingKeyId.isNotBlank()) { "sharingKeyId must not be empty." }
    require(context.credentialId.isNotBlank()) { "credentialId must not be empty." }
}

private fun parseObject(value: String, label: String): JsonObject = try {
    SyncKitJson.instance.parseToJsonElement(value).jsonObject
} catch (error: Exception) {
    throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, "The $label is invalid.", error)
}

private fun JsonObject.string(name: String): String? = this[name]?.jsonPrimitive?.contentOrNull
private fun JsonObject.requiredString(name: String): String = string(name)?.takeIf(String::isNotBlank)
    ?: compatibility("$name must be a non-empty string.")
private fun JsonObject.objectValue(name: String): JsonObject = this[name]?.jsonObject
    ?: compatibility("$name must be an object.")
private fun JsonObject.long(name: String): Long? = this[name]?.jsonPrimitive?.longOrNull
private fun JsonObject.audiences(): List<String> = when (val value = this["aud"]) {
    is JsonArray -> value.mapNotNull { it.jsonPrimitive.contentOrNull }
    else -> value?.jsonPrimitive?.contentOrNull?.let(::listOf).orEmpty()
}

private fun authorization(message: String): Nothing = throw SyncKitError(SyncKitErrorCode.AUTHORIZATION, message)
private fun compatibility(message: String): Nothing = throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, message)
