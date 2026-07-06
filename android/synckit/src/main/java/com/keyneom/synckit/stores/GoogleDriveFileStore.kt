package com.keyneom.synckit.stores

import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.UUID

data class DriveObject(
    val fileId: String,
    val name: String,
    val modifiedTime: String? = null,
)

data class DriveUser(
    val displayName: String? = null,
    val permissionId: String? = null,
    val emailAddress: String? = null,
    val me: Boolean? = null,
)

data class DriveFileMetadata(
    val fileId: String,
    val name: String,
    val mimeType: String? = null,
    val modifiedTime: String? = null,
    val parents: List<String>? = null,
    val appProperties: Map<String, String>? = null,
    val createdTime: String? = null,
    val version: String? = null,
    val headRevisionId: String? = null,
    val etag: String? = null,
    val inheritedPermissionsDisabled: Boolean? = null,
    val owners: List<DriveUser>? = null,
    val sharingUser: DriveUser? = null,
    val lastModifyingUser: DriveUser? = null,
    val capabilities: DriveCapabilities? = null,
)

data class DriveCapabilities(
    val canEdit: Boolean? = null,
    val canShare: Boolean? = null,
    val canDelete: Boolean? = null,
    val canListChildren: Boolean? = null,
    val canDisableInheritedPermissions: Boolean? = null,
    val canEnableInheritedPermissions: Boolean? = null,
)

data class DriveFileList(
    val files: List<DriveFileMetadata>,
    val nextPageToken: String? = null,
)

data class DriveFileContent(
    val content: String,
    val etag: String? = null,
)

data class DriveFileWriteResult(
    val fileId: String,
    val etag: String? = null,
)

data class DriveV2WriteHead(
    val etag: String,
    val headRevisionId: String? = null,
)

data class DriveV2WriteResult(
    val fileId: String,
    val etag: String,
    val headRevisionId: String? = null,
)

class DriveV2UnavailableException(
    cause: SyncKitError,
) : Exception(cause.message, cause)

data class DrivePermission(
    val permissionId: String,
    val type: String,
    val role: String,
    val emailAddress: String? = null,
    val displayName: String? = null,
    val inherited: Boolean = false,
)

data class DriveFileProvenanceExpectation(
    val permissionId: String? = null,
    val emailAddress: String? = null,
    val sharingUserPermissionId: String? = null,
)

open class GoogleDriveFileStore(
    private val options: GoogleDriveStoreOptions = GoogleDriveStoreOptions(),
) {
    suspend fun get(fileId: String, authorization: Authorization): DriveFileMetadata =
        withContext(Dispatchers.IO) {
            val params = "fields=" + encodeQuery(
                "id,name,mimeType,createdTime,modifiedTime,version,headRevisionId,parents," +
                    "appProperties,inheritedPermissionsDisabled," +
                    "owners(displayName,permissionId,emailAddress,me)," +
                    "sharingUser(displayName,permissionId,emailAddress,me)," +
                    "lastModifyingUser(displayName,permissionId,emailAddress,me)," +
                    "capabilities(canEdit,canShare,canDelete,canListChildren," +
                    "canDisableInheritedPermissions,canEnableInheritedPermissions)",
            ) + "&supportsAllDrives=true"
            val response = request(
                "${options.apiOrigin}/drive/v3/files/${encodePathSegment(fileId)}?$params",
                authorization.accessToken,
            )
            driveFileMetadata(
                SyncKitJson.instance.parseToJsonElement(response.body).jsonObject,
                response.headers["ETag"],
            )
        }

    suspend fun list(
        authorization: Authorization,
        parentId: String? = null,
        appProperties: Map<String, String>? = null,
        pageToken: String? = null,
        pageSize: Int = 100,
    ): DriveFileList = withContext(Dispatchers.IO) {
        val clauses = mutableListOf("trashed = false")
        parentId?.let { clauses += "'${escapeDriveQuery(it)}' in parents" }
        appProperties?.forEach { (key, value) ->
            clauses += "appProperties has { key='${escapeDriveQuery(key)}' and value='${escapeDriveQuery(value)}' }"
        }
        val params = buildString {
            append("spaces=drive&corpora=user")
            append("&q=").append(encodeQuery(clauses.joinToString(" and ")))
            append("&fields=").append(
                encodeQuery(
                    "nextPageToken,files(id,name,mimeType,modifiedTime,version,headRevisionId,parents,appProperties,capabilities(canEdit,canShare,canDelete))",
                ),
            )
            append("&pageSize=$pageSize&supportsAllDrives=true&includeItemsFromAllDrives=true")
            pageToken?.let { append("&pageToken=").append(encodeQuery(it)) }
        }
        val response = request(
            "${options.apiOrigin}/drive/v3/files?$params",
            authorization.accessToken,
        )
        val root = SyncKitJson.instance.parseToJsonElement(response.body).jsonObject
        DriveFileList(
            files = root["files"]?.jsonArray?.map {
                driveFileMetadata(it.jsonObject)
            }.orEmpty(),
            nextPageToken = root["nextPageToken"]?.jsonPrimitive?.content,
        )
    }

    suspend fun readText(fileId: String, authorization: Authorization): String =
        readTextVersioned(fileId, authorization).content

    suspend fun readTextVersioned(
        fileId: String,
        authorization: Authorization,
    ): DriveFileContent = withContext(Dispatchers.IO) {
        val content = request(
            "${options.apiOrigin}/drive/v3/files/${encodePathSegment(fileId)}" +
                "?alt=media&supportsAllDrives=true",
            authorization.accessToken,
        )
        DriveFileContent(content.body, content.headers["ETag"])
    }

    suspend fun create(
        name: String,
        content: String,
        authorization: Authorization,
        parentId: String? = null,
        contentType: String = "application/octet-stream",
        appProperties: Map<String, String>? = null,
        writersCanShare: Boolean = false,
    ): String = withContext(Dispatchers.IO) {
        val boundary = "sync-kit-${UUID.randomUUID()}"
        val metadata = buildJsonObject {
            put("name", name)
            parentId?.let { put("parents", SyncKitJson.instance.parseToJsonElement("""["$it"]""")) }
            appProperties?.let { props ->
                put("appProperties", buildJsonObject {
                    props.forEach { (key, value) -> put(key, value) }
                })
            }
            put("writersCanShare", writersCanShare)
        }
        val multipart = buildString {
            append("--$boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n")
            append(SyncKitJson.instance.encodeToString(JsonObject.serializer(), metadata))
            append("\r\n--$boundary\r\nContent-Type: $contentType\r\n\r\n")
            append(content)
            append("\r\n--$boundary--")
        }.toByteArray(Charsets.UTF_8)
        val response = request(
            "${options.uploadOrigin}/upload/drive/v3/files?uploadType=multipart&fields=id&supportsAllDrives=true",
            authorization.accessToken,
            method = "POST",
            contentType = "multipart/related; boundary=$boundary",
            body = multipart,
        )
        responseFileId(response.body)
    }

    suspend fun createFolder(
        name: String,
        authorization: Authorization,
        parentId: String? = null,
        appProperties: Map<String, String>? = null,
        writersCanShare: Boolean = false,
    ): String = withContext(Dispatchers.IO) {
        val metadata = buildJsonObject {
            put("name", name)
            put("mimeType", DRIVE_FOLDER_MIME_TYPE)
            parentId?.let { put("parents", SyncKitJson.instance.parseToJsonElement("""["$it"]""")) }
            appProperties?.let { props ->
                put("appProperties", buildJsonObject {
                    props.forEach { (key, value) -> put(key, value) }
                })
            }
            put("writersCanShare", writersCanShare)
        }
        val response = request(
            "${options.apiOrigin}/drive/v3/files?fields=id&supportsAllDrives=true",
            authorization.accessToken,
            method = "POST",
            contentType = "application/json",
            body = SyncKitJson.instance.encodeToString(JsonObject.serializer(), metadata)
                .toByteArray(Charsets.UTF_8),
        )
        responseFileId(response.body)
    }

    suspend fun write(
        fileId: String,
        content: String,
        authorization: Authorization,
        contentType: String = "application/octet-stream",
        ifMatch: String? = null,
    ): DriveFileWriteResult = withContext(Dispatchers.IO) {
        val extraHeaders = ifMatch?.let { mapOf("If-Match" to it) }.orEmpty()
        val response = request(
            "${options.uploadOrigin}/upload/drive/v3/files/${encodePathSegment(fileId)}" +
                "?uploadType=media&fields=id&supportsAllDrives=true",
            authorization.accessToken,
            method = "POST",
            contentType = contentType,
            body = content.toByteArray(Charsets.UTF_8),
            extraHeaders = extraHeaders + mapOf("X-HTTP-Method-Override" to "PATCH"),
        )
        DriveFileWriteResult(fileId, response.headers["ETag"])
    }

    suspend fun getV2WriteHead(
        fileId: String,
        authorization: Authorization,
    ): DriveV2WriteHead = withContext(Dispatchers.IO) {
        try {
            val response = request(
                "${options.apiOrigin}/drive/v2/files/${encodePathSegment(fileId)}" +
                    "?fields=etag,headRevisionId",
                authorization.accessToken,
            )
            val root = SyncKitJson.instance.parseToJsonElement(response.body).jsonObject
            val etag = root["etag"]?.jsonPrimitive?.content
                ?: throw providerError("Google Drive v2 metadata did not include an etag.")
            DriveV2WriteHead(
                etag = etag,
                headRevisionId = root["headRevisionId"]?.jsonPrimitive?.content,
            )
        } catch (error: SyncKitError) {
            if (isDriveV2EndpointUnavailable(error)) {
                throw DriveV2UnavailableException(error)
            }
            throw error
        }
    }

    suspend fun writeV2Media(
        fileId: String,
        content: String,
        authorization: Authorization,
        contentType: String = "application/octet-stream",
        ifMatch: String,
    ): DriveV2WriteResult = withContext(Dispatchers.IO) {
        try {
            val response = request(
                "${options.uploadOrigin}/upload/drive/v2/files/${encodePathSegment(fileId)}" +
                    "?uploadType=media&fields=etag,headRevisionId",
                authorization.accessToken,
                method = "PUT",
                contentType = contentType,
                body = content.toByteArray(Charsets.UTF_8),
                extraHeaders = mapOf("If-Match" to ifMatch),
            )
            val root = SyncKitJson.instance.parseToJsonElement(response.body).jsonObject
            val etag = root["etag"]?.jsonPrimitive?.content
                ?: throw providerError("Google Drive v2 upload did not return an etag.")
            DriveV2WriteResult(
                fileId = fileId,
                etag = etag,
                headRevisionId = root["headRevisionId"]?.jsonPrimitive?.content,
            )
        } catch (error: SyncKitError) {
            if (isDriveV2EndpointUnavailable(error)) {
                throw DriveV2UnavailableException(error)
            }
            throw error
        }
    }

    suspend fun share(
        fileId: String,
        emailAddress: String,
        role: String,
        authorization: Authorization,
        sendNotificationEmail: Boolean = true,
        emailMessage: String? = null,
    ): String = withContext(Dispatchers.IO) {
        val params = buildString {
            append("fields=id&supportsAllDrives=true")
            append("&sendNotificationEmail=$sendNotificationEmail")
            emailMessage?.let {
                append("&emailMessage=").append(encodeQuery(it))
            }
        }
        val body = buildJsonObject {
            put("type", "user")
            put("role", role)
            put("emailAddress", emailAddress)
        }
        val response = request(
            "${options.apiOrigin}/drive/v3/files/${encodePathSegment(fileId)}/permissions?$params",
            authorization.accessToken,
            method = "POST",
            contentType = "application/json",
            body = SyncKitJson.instance.encodeToString(JsonObject.serializer(), body)
                .toByteArray(Charsets.UTF_8),
        )
        responseFileId(response.body)
    }

    suspend fun removePermission(
        fileId: String,
        permissionId: String,
        authorization: Authorization,
    ) = withContext(Dispatchers.IO) {
        request(
            "${options.apiOrigin}/drive/v3/files/${encodePathSegment(fileId)}" +
                "/permissions/${encodePathSegment(permissionId)}?supportsAllDrives=true",
            authorization.accessToken,
            method = "DELETE",
        )
    }

    suspend fun listPermissions(
        fileId: String,
        authorization: Authorization,
    ): List<DrivePermission> = withContext(Dispatchers.IO) {
        val params = "fields=" + encodeQuery(
            "permissions(id,type,role,emailAddress,displayName,permissionDetails(inherited))",
        ) + "&supportsAllDrives=true"
        val response = request(
            "${options.apiOrigin}/drive/v3/files/${encodePathSegment(fileId)}/permissions?$params",
            authorization.accessToken,
        )
        val permissions = SyncKitJson.instance.parseToJsonElement(response.body).jsonObject["permissions"]
            ?.jsonArray.orEmpty()
        permissions.map { permission ->
            val obj = permission.jsonObject
            DrivePermission(
                permissionId = obj["id"]?.jsonPrimitive?.content
                    ?: throw providerError("Google Drive returned incomplete permission metadata."),
                type = obj["type"]?.jsonPrimitive?.content
                    ?: throw providerError("Google Drive returned incomplete permission metadata."),
                role = obj["role"]?.jsonPrimitive?.content
                    ?: throw providerError("Google Drive returned incomplete permission metadata."),
                emailAddress = obj["emailAddress"]?.jsonPrimitive?.content,
                displayName = obj["displayName"]?.jsonPrimitive?.content,
                inherited = obj["permissionDetails"]?.jsonArray?.any {
                    it.jsonObject["inherited"]?.jsonPrimitive?.content == "true"
                } == true,
            )
        }
    }

    suspend fun updatePermission(
        fileId: String,
        permissionId: String,
        role: String,
        authorization: Authorization,
    ) = withContext(Dispatchers.IO) {
        val body = buildJsonObject { put("role", role) }
        request(
            "${options.apiOrigin}/drive/v3/files/${encodePathSegment(fileId)}" +
                "/permissions/${encodePathSegment(permissionId)}?supportsAllDrives=true",
            authorization.accessToken,
            method = "POST",
            contentType = "application/json",
            body = SyncKitJson.instance.encodeToString(JsonObject.serializer(), body)
                .toByteArray(Charsets.UTF_8),
            extraHeaders = mapOf("X-HTTP-Method-Override" to "PATCH"),
        )
    }

    suspend fun delete(fileId: String, authorization: Authorization) =
        withContext(Dispatchers.IO) {
            request(
                "${options.apiOrigin}/drive/v3/files/${encodePathSegment(fileId)}?supportsAllDrives=true",
                authorization.accessToken,
                method = "DELETE",
            )
        }

    protected open fun request(
        url: String,
        accessToken: String,
        method: String = "GET",
        contentType: String? = null,
        body: ByteArray? = null,
        extraHeaders: Map<String, String> = emptyMap(),
    ): DriveHttpResponse {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.setRequestProperty("Authorization", "Bearer $accessToken")
            connection.connectTimeout = 20_000
            connection.readTimeout = 30_000
            contentType?.let { connection.setRequestProperty("Content-Type", it) }
            for ((name, value) in extraHeaders) {
                connection.setRequestProperty(name, value)
            }
            if (body != null) {
                connection.doOutput = true
                connection.outputStream.use { it.write(body) }
            }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val response = stream?.use { it.readBytes().toString(Charsets.UTF_8) }.orEmpty()
            val responseHeaders = driveResponseHeaders(connection.headerFields)
            if (code !in 200..299) {
                if (code == 401) options.onUnauthorized?.invoke()
                throw SyncKitError(
                    when (code) {
                        401 -> SyncKitErrorCode.AUTHORIZATION
                        404 -> SyncKitErrorCode.NOT_FOUND
                        409, 412 -> SyncKitErrorCode.CONFLICT
                        else -> SyncKitErrorCode.NETWORK
                    },
                    "Google Drive request failed ($code). ${response.take(400)}",
                    httpStatus = code,
                )
            }
            return DriveHttpResponse(response, responseHeaders)
        } finally {
            connection.disconnect()
        }
    }

    private fun encodePathSegment(value: String): String =
        URLEncoder.encode(value, Charsets.UTF_8.name())

    private fun encodeQuery(value: String): String =
        URLEncoder.encode(value, Charsets.UTF_8.name())

    private fun responseFileId(response: String): String =
        SyncKitJson.instance.parseToJsonElement(response).jsonObject["id"]?.jsonPrimitive?.content
            ?: throw providerError("Google Drive did not return a file ID.")

    private fun providerError(message: String): SyncKitError =
        SyncKitError(SyncKitErrorCode.NETWORK, message)

    private fun driveFileMetadata(
        value: JsonObject,
        etag: String? = null,
    ): DriveFileMetadata {
        val id = value["id"]?.jsonPrimitive?.content
        val name = value["name"]?.jsonPrimitive?.content
        if (id.isNullOrBlank() || name.isNullOrBlank()) {
            throw providerError("Google Drive returned incomplete file metadata.")
        }
        return DriveFileMetadata(
            fileId = id,
            name = name,
            mimeType = value["mimeType"]?.jsonPrimitive?.content,
            modifiedTime = value["modifiedTime"]?.jsonPrimitive?.content,
            createdTime = value["createdTime"]?.jsonPrimitive?.content,
            version = value["version"]?.jsonPrimitive?.content,
            headRevisionId = value["headRevisionId"]?.jsonPrimitive?.content,
            etag = etag ?: value["etag"]?.jsonPrimitive?.content,
            inheritedPermissionsDisabled = value["inheritedPermissionsDisabled"]?.jsonPrimitive?.content?.toBooleanStrictOrNull(),
            parents = value["parents"]?.jsonArray?.map { it.jsonPrimitive.content },
            appProperties = value["appProperties"]?.jsonObject?.mapValues { it.value.jsonPrimitive.content },
            owners = parseUsers(value["owners"]?.jsonArray),
            sharingUser = parseUser(value["sharingUser"]?.jsonObject),
            lastModifyingUser = parseUser(value["lastModifyingUser"]?.jsonObject),
            capabilities = value["capabilities"]?.jsonObject?.let { caps ->
                DriveCapabilities(
                    canEdit = caps["canEdit"]?.jsonPrimitive?.content?.toBooleanStrictOrNull(),
                    canShare = caps["canShare"]?.jsonPrimitive?.content?.toBooleanStrictOrNull(),
                    canDelete = caps["canDelete"]?.jsonPrimitive?.content?.toBooleanStrictOrNull(),
                    canListChildren = caps["canListChildren"]?.jsonPrimitive?.content?.toBooleanStrictOrNull(),
                    canDisableInheritedPermissions = caps["canDisableInheritedPermissions"]?.jsonPrimitive?.content?.toBooleanStrictOrNull(),
                    canEnableInheritedPermissions = caps["canEnableInheritedPermissions"]?.jsonPrimitive?.content?.toBooleanStrictOrNull(),
                )
            },
        )
    }

    private fun parseUsers(array: kotlinx.serialization.json.JsonArray?): List<DriveUser>? =
        array?.mapNotNull { parseUser(it.jsonObject) }

    private fun parseUser(obj: JsonObject?): DriveUser? {
        obj ?: return null
        return DriveUser(
            displayName = obj["displayName"]?.jsonPrimitive?.content,
            permissionId = obj["permissionId"]?.jsonPrimitive?.content,
            emailAddress = obj["emailAddress"]?.jsonPrimitive?.content,
            me = obj["me"]?.jsonPrimitive?.content?.toBooleanStrictOrNull(),
        )
    }
}

data class GoogleDriveStoreOptions(
    val apiOrigin: String = "https://www.googleapis.com",
    val uploadOrigin: String = "https://www.googleapis.com",
    val onUnauthorized: (() -> Unit)? = null,
)

data class DriveHttpResponse(
    val body: String,
    val headers: Map<String, String>,
)

// HTTP/2 (which Android negotiates with googleapis.com) delivers all header
// names lowercase; a case-insensitive map keeps lookups like "ETag" working.
internal fun driveResponseHeaders(fields: Map<String?, List<String>>): Map<String, String> {
    val headers = java.util.TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER)
    for ((name, values) in fields) {
        if (name != null) headers[name] = values.firstOrNull().orEmpty()
    }
    return headers
}

private fun isDriveV2EndpointUnavailable(error: SyncKitError): Boolean =
    error.httpStatus == 404 || error.httpStatus == 410

fun assertDriveFileProvenance(
    file: DriveFileMetadata,
    expected: DriveFileProvenanceExpectation,
) {
    require(!expected.permissionId.isNullOrBlank() || !expected.emailAddress.isNullOrBlank()) {
        "Expected permissionId or emailAddress is required."
    }
    if (file.owners?.size != 1) {
        throw SyncKitError(
            SyncKitErrorCode.AUTHORIZATION,
            "The exchange response is not a singly owned My Drive file.",
        )
    }
    val owner = file.owners.first()
    if (!driveUserMatches(owner, expected)) {
        throw SyncKitError(
            SyncKitErrorCode.AUTHORIZATION,
            "The exchange response is not owned by the expected Google account.",
        )
    }
    val lastModifying = file.lastModifyingUser
        ?: throw SyncKitError(
            SyncKitErrorCode.AUTHORIZATION,
            "The exchange response was modified by another Google account.",
        )
    if (!driveUserMatches(lastModifying, expected)) {
        throw SyncKitError(
            SyncKitErrorCode.AUTHORIZATION,
            "The exchange response was modified by another Google account.",
        )
    }
    expected.sharingUserPermissionId?.let { expectedPermission ->
        if (file.sharingUser?.permissionId != expectedPermission) {
            throw SyncKitError(
                SyncKitErrorCode.AUTHORIZATION,
                "The exchange response has unexpected sharing provenance.",
            )
        }
    }
}

private fun driveUserMatches(user: DriveUser, expected: DriveFileProvenanceExpectation): Boolean {
    expected.permissionId?.let { return user.permissionId == it }
    return user.emailAddress?.lowercase() == expected.emailAddress?.lowercase()
}
