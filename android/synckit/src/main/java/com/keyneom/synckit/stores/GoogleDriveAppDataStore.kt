package com.keyneom.synckit.stores

import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.core.CloudStore
import com.keyneom.synckit.core.StoredEnvelope
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.SyncEnvelopeV1
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.crypto.V1CompatibilityProfile
import com.keyneom.synckit.crypto.V1EnvelopeCrypto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
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
 * Google Drive `appDataFolder` store for private v1 snapshots.
 * Filename and envelope validation come from the consumer profile.
 */
open class GoogleDriveAppDataStore<T>(
    private val profile: V1CompatibilityProfile,
    private val envelopeCrypto: V1EnvelopeCrypto<T>,
) : CloudStore {
    override suspend fun find(
        appId: String,
        authorization: Authorization,
    ): StoredEnvelope? = withContext(Dispatchers.IO) {
        requireAppId(appId)
        val query = URLEncoder.encode(
            "name = '${profile.filename}' and trashed = false",
            Charsets.UTF_8.name(),
        )
        val url = "https://www.googleapis.com/drive/v3/files" +
            "?spaces=appDataFolder&q=$query&fields=files(id,name,modifiedTime)&pageSize=1"
        val listed = request(url, authorization.accessToken)
        val root = SyncKitJson.instance.parseToJsonElement(listed).jsonObject
        val fileId = root["files"]?.jsonArray?.firstOrNull()?.jsonObject
            ?.get("id")?.jsonPrimitive?.content ?: return@withContext null
        val body = request(
            "https://www.googleapis.com/drive/v3/files/${encode(fileId)}?alt=media",
            authorization.accessToken,
        )
        StoredEnvelope(fileId, envelopeCrypto.parseEnvelope(body))
    }

    override suspend fun write(
        appId: String,
        envelope: SyncEnvelopeV1,
        authorization: Authorization,
        existingId: String?,
    ): String = withContext(Dispatchers.IO) {
        requireAppId(appId)
        envelopeCrypto.validateEnvelope(envelope)
        val content = envelopeCrypto.encodeEnvelope(envelope)
        if (existingId != null) {
            request(
                "https://www.googleapis.com/upload/drive/v3/files/${encode(existingId)}?uploadType=media&fields=id",
                authorization.accessToken,
                method = "PATCH",
                contentType = "application/json",
                body = content.toByteArray(Charsets.UTF_8),
            )
            return@withContext existingId
        }

        val boundary = "sync-kit-${UUID.randomUUID()}"
        val metadata = SyncKitJson.instance.encodeToString(
            JsonObject.serializer(),
            buildJsonObject {
                put("name", profile.filename)
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
        val response = request(
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id",
            authorization.accessToken,
            method = "POST",
            contentType = "multipart/related; boundary=$boundary",
            body = multipart,
        )
        SyncKitJson.instance.parseToJsonElement(response).jsonObject["id"]?.jsonPrimitive?.content
            ?: throw SyncKitError(
                SyncKitErrorCode.NETWORK,
                "Google Drive did not return a file id.",
            )
    }

    override suspend fun delete(
        appId: String,
        fileId: String,
        authorization: Authorization,
    ) = withContext(Dispatchers.IO) {
        requireAppId(appId)
        request(
            "https://www.googleapis.com/drive/v3/files/${encode(fileId)}",
            authorization.accessToken,
            method = "DELETE",
        )
        Unit
    }

    private fun requireAppId(appId: String) {
        if (appId != profile.appId) {
            throw SyncKitError(
                SyncKitErrorCode.CONFIGURATION,
                "Cloud store profile appId is ${profile.appId}, not $appId.",
            )
        }
    }

    private fun request(
        url: String,
        accessToken: String,
        method: String = "GET",
        contentType: String? = null,
        body: ByteArray? = null,
    ): String {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.setRequestProperty("Authorization", "Bearer $accessToken")
            connection.connectTimeout = 20_000
            connection.readTimeout = 30_000
            if (contentType != null) connection.setRequestProperty("Content-Type", contentType)
            if (body != null) {
                connection.doOutput = true
                connection.outputStream.use { it.write(body) }
            }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val response = stream?.use { it.readBytes().toString(Charsets.UTF_8) }.orEmpty()
            if (code !in 200..299) {
                throw SyncKitError(
                    SyncKitErrorCode.NETWORK,
                    "Google Drive request failed ($code). ${response.take(400)}",
                )
            }
            return response
        } finally {
            connection.disconnect()
        }
    }

    private fun encode(value: String): String = URLEncoder.encode(value, Charsets.UTF_8.name())
}
