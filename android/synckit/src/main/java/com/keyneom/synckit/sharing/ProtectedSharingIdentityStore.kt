package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.UUID

/**
 * Persists the passkey-wrapped sharing identity. Mirrors the web
 * `ProtectedSharingIdentityStore` so both platforms can host the identity in
 * the same substrate (`drive.appdata`).
 */
interface ProtectedSharingIdentityStore {
    suspend fun load(appId: String): ProtectedSharingIdentityV1?
    suspend fun save(record: ProtectedSharingIdentityV1)
    suspend fun delete(appId: String)
}

/**
 * Reads [primary] first (authoritative, e.g. `drive.appdata`) and falls back to
 * a pre-existing [legacy] store, promoting the legacy record to primary on the
 * first hit. Promotion is best-effort so a returning user never regenerates a
 * fresh identity and loses access to their dataset when the promotion write
 * fails. Mirrors the web MigratingProtectedSharingIdentityStore.
 *
 * Note: this bridges two stores that both already hold wrapped records. Android's
 * pre-passkey identities are raw keypairs, not wrapped records; that migration
 * is handled where the passkey is available (the consumer), by wrapping the raw
 * identity before it reaches this store.
 */
class MigratingProtectedSharingIdentityStore(
    private val primary: ProtectedSharingIdentityStore,
    private val legacy: ProtectedSharingIdentityStore,
) : ProtectedSharingIdentityStore {
    override suspend fun load(appId: String): ProtectedSharingIdentityV1? {
        primary.load(appId)?.let { return it }
        val legacyRecord = legacy.load(appId) ?: return null
        runCatching { primary.save(legacyRecord) }
        return legacyRecord
    }

    override suspend fun save(record: ProtectedSharingIdentityV1) = primary.save(record)

    override suspend fun delete(appId: String) {
        primary.delete(appId)
        runCatching { legacy.delete(appId) }
    }
}

/**
 * Hosts the wrapped sharing identity in the signed-in Google account's private
 * `drive.appdata` folder, which the same account returns on any device — the
 * substrate that carries one sharing identity across a user's devices. The
 * record is already AES-GCM-encrypted with the passkey PRF secret, so Drive only
 * ever sees an opaque blob.
 */
open class DriveAppDataProtectedSharingIdentityStore(
    private val authorization: suspend () -> Authorization,
    private val filename: (appId: String) -> String = { "sync-kit-sharing-identity-$it.json" },
    private val apiOrigin: String = "https://www.googleapis.com",
    private val uploadOrigin: String = "https://www.googleapis.com",
) : ProtectedSharingIdentityStore {
    override suspend fun load(appId: String): ProtectedSharingIdentityV1? =
        withContext(Dispatchers.IO) {
            val token = authorization().accessToken
            val fileId = findFileId(filename(appId), token) ?: return@withContext null
            val body = request(
                "$apiOrigin/drive/v3/files/${encode(fileId)}?alt=media",
                token,
            )
            ProtectedSharingIdentityCrypto.parse(body)
        }

    override suspend fun save(record: ProtectedSharingIdentityV1) =
        withContext(Dispatchers.IO) {
            val token = authorization().accessToken
            val name = filename(record.appId)
            val content = SyncKitJson.instance.encodeToString(
                ProtectedSharingIdentityV1.serializer(),
                record,
            )
            val existingId = findFileId(name, token)
            if (existingId != null) {
                // HttpURLConnection rejects PATCH; Drive accepts POST + override.
                request(
                    "$uploadOrigin/upload/drive/v3/files/${encode(existingId)}" +
                        "?uploadType=media&fields=id",
                    token,
                    method = "POST",
                    contentType = "application/json",
                    body = content.toByteArray(Charsets.UTF_8),
                    extraHeaders = mapOf("X-HTTP-Method-Override" to "PATCH"),
                )
            } else {
                val boundary = "sync-kit-${UUID.randomUUID()}"
                val metadata = SyncKitJson.instance.encodeToString(
                    kotlinx.serialization.json.JsonObject.serializer(),
                    buildJsonObject {
                        put("name", name)
                        put("parents", buildJsonArray {
                            add(kotlinx.serialization.json.JsonPrimitive("appDataFolder"))
                        })
                    },
                )
                val multipart = buildString {
                    append("--$boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n")
                    append(metadata)
                    append("\r\n--$boundary\r\nContent-Type: application/json\r\n\r\n")
                    append(content)
                    append("\r\n--$boundary--")
                }.toByteArray(Charsets.UTF_8)
                request(
                    "$uploadOrigin/upload/drive/v3/files?uploadType=multipart&fields=id",
                    token,
                    method = "POST",
                    contentType = "multipart/related; boundary=$boundary",
                    body = multipart,
                )
            }
            Unit
        }

    override suspend fun delete(appId: String) =
        withContext(Dispatchers.IO) {
            val token = authorization().accessToken
            val fileId = findFileId(filename(appId), token) ?: return@withContext
            request(
                "$apiOrigin/drive/v3/files/${encode(fileId)}",
                token,
                method = "DELETE",
            )
            Unit
        }

    private fun findFileId(name: String, token: String): String? {
        val query = URLEncoder.encode(
            "name = '${escapeDriveQuery(name)}' and trashed = false",
            Charsets.UTF_8.name(),
        )
        val listed = request(
            "$apiOrigin/drive/v3/files?spaces=appDataFolder&q=$query" +
                "&fields=files(id,name)&pageSize=1",
            token,
        )
        return SyncKitJson.instance.parseToJsonElement(listed).jsonObject["files"]
            ?.jsonArray?.firstOrNull()?.jsonObject?.get("id")?.jsonPrimitive?.content
    }

    protected open fun request(
        url: String,
        accessToken: String,
        method: String = "GET",
        contentType: String? = null,
        body: ByteArray? = null,
        extraHeaders: Map<String, String> = emptyMap(),
    ): String {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.setRequestProperty("Authorization", "Bearer $accessToken")
            connection.connectTimeout = 20_000
            connection.readTimeout = 30_000
            if (contentType != null) connection.setRequestProperty("Content-Type", contentType)
            for ((name, value) in extraHeaders) connection.setRequestProperty(name, value)
            if (body != null) {
                connection.doOutput = true
                connection.outputStream.use { it.write(body) }
            }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val response = stream?.use { it.readBytes().toString(Charsets.UTF_8) }.orEmpty()
            if (code !in 200..299) {
                throw SyncKitError(
                    when (code) {
                        401 -> SyncKitErrorCode.AUTHORIZATION
                        404 -> SyncKitErrorCode.NOT_FOUND
                        else -> SyncKitErrorCode.NETWORK
                    },
                    "Google Drive appdata request failed ($code). ${response.take(400)}",
                )
            }
            return response
        } finally {
            connection.disconnect()
        }
    }

    private fun encode(value: String): String = URLEncoder.encode(value, Charsets.UTF_8.name())

    private fun escapeDriveQuery(value: String): String =
        value.replace("\\", "\\\\").replace("'", "\\'")
}
