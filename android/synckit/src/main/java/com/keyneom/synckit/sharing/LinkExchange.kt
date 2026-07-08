package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Link-carried key exchange (Kotlin parity with src/sharing/link-exchange.ts).
 * The signed invitation and key response travel in the join/response links
 * (base64url of the existing structs) rather than Drive `exchanges/` files, so a
 * `drive.file` recipient never reads a file the owner authored and the owner
 * never reads a file the recipient authored. See docs/sync-kit-linkbased-join.md.
 */

const val SHARING_JOIN_INVITATION_PARAM = "sk-inv"
const val SHARING_JOIN_FILES_PARAM = "sk-files"
const val SHARING_RESPONSE_MARKER_PARAM = "sk-resp"
const val SHARING_RESPONSE_PAYLOAD_PARAM = "sk-kr"

/** A dataset file the recipient is granted, so the Picker can offer it by id. */
@Serializable
data class SharingDatasetFileV1(
    val datasetId: String,
    val fileId: String,
    val role: SharingRole,
)

data class SharingJoinLinkV1(
    val invitation: SharingInvitationV1,
    val files: List<SharingDatasetFileV1>,
)

data class SharingResponseLinkV1(
    val response: SharingPublicKeyResponseV1,
)

/** Owner-side result of a link-carried invite: what to embed in the join link. */
data class SharingLinkInvite(
    val invitation: SharingInvitationV1,
    val files: List<SharingDatasetFileV1>,
)

/**
 * Placeholder recipient permission id for the link-carried exchange (no Drive
 * exchange grant). Set identically on the invitation and passed to accept so the
 * anti-substitution equality check passes; provenance comes from the response
 * signature, not a Drive permission.
 */
const val SHARING_LINK_PERMISSION_ID = "link"

// --- payload encode/decode (signed structs unchanged; only transported) ---

fun encodeSharingInvitationV1(invitation: SharingInvitationV1): String =
    encodeJson(
        SharingCrypto.parseSharingInvitationV1(invitation),
        SharingInvitationV1.serializer(),
    )

fun decodeSharingInvitationV1(encoded: String): SharingInvitationV1 =
    SharingCrypto.parseSharingInvitationV1(
        decodeJson(encoded, "invitation", SharingInvitationV1.serializer()),
    )

fun encodeSharingPublicKeyResponseV1(response: SharingPublicKeyResponseV1): String =
    encodeJson(
        SharingCrypto.parseSharingPublicKeyResponseV1(response),
        SharingPublicKeyResponseV1.serializer(),
    )

fun decodeSharingPublicKeyResponseV1(encoded: String): SharingPublicKeyResponseV1 =
    SharingCrypto.parseSharingPublicKeyResponseV1(
        decodeJson(encoded, "key response", SharingPublicKeyResponseV1.serializer()),
    )

fun encodeSharingDatasetFilesV1(files: List<SharingDatasetFileV1>): String {
    if (files.isEmpty()) {
        throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, "A join link needs at least one dataset file.")
    }
    return encodeJson(files.map(::normalizeDatasetFile), ListSerializer(SharingDatasetFileV1.serializer()))
}

fun decodeSharingDatasetFilesV1(encoded: String): List<SharingDatasetFileV1> {
    val files = decodeJson(encoded, "dataset files", ListSerializer(SharingDatasetFileV1.serializer()))
    if (files.isEmpty()) {
        throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, "The join link dataset file list is malformed.")
    }
    return files.map(::normalizeDatasetFile)
}

// --- link builders / parsers ---

fun buildSharingJoinLinkV1(
    landingUrl: String,
    invitation: SharingInvitationV1,
    files: List<SharingDatasetFileV1>,
): String = appendQueryParams(
    landingUrl,
    linkedMapOf(
        SHARING_JOIN_MARKER_PARAM to "1",
        SHARING_JOIN_FOLDER_PARAM to invitation.appFolderId,
        SHARING_JOIN_EXCHANGE_PARAM to invitation.exchangeId,
        SHARING_JOIN_INVITATION_PARAM to encodeSharingInvitationV1(invitation),
        SHARING_JOIN_FILES_PARAM to encodeSharingDatasetFilesV1(files),
    ),
)

fun parseSharingJoinLinkV1(input: String): SharingJoinLinkV1? {
    val params = parseQuery(input)
    val invitation = params[SHARING_JOIN_INVITATION_PARAM]
    val files = params[SHARING_JOIN_FILES_PARAM]
    if (invitation.isNullOrEmpty() || files.isNullOrEmpty()) return null
    return SharingJoinLinkV1(
        invitation = decodeSharingInvitationV1(invitation),
        files = decodeSharingDatasetFilesV1(files),
    )
}

fun buildSharingResponseLinkV1(
    landingUrl: String,
    response: SharingPublicKeyResponseV1,
): String = appendQueryParams(
    landingUrl,
    linkedMapOf(
        SHARING_RESPONSE_MARKER_PARAM to "1",
        SHARING_JOIN_EXCHANGE_PARAM to response.exchangeId,
        SHARING_RESPONSE_PAYLOAD_PARAM to encodeSharingPublicKeyResponseV1(response),
    ),
)

fun parseSharingResponseLinkV1(input: String): SharingResponseLinkV1? {
    val params = parseQuery(input)
    if (params[SHARING_RESPONSE_MARKER_PARAM] != "1") return null
    val response = params[SHARING_RESPONSE_PAYLOAD_PARAM]
    if (response.isNullOrEmpty()) return null
    return SharingResponseLinkV1(decodeSharingPublicKeyResponseV1(response))
}

// --- internals ---

private fun <T> encodeJson(value: T, serializer: kotlinx.serialization.KSerializer<T>): String =
    Base64Url.encode(
        SyncKitJson.instance.encodeToString(serializer, value).toByteArray(StandardCharsets.UTF_8),
    )

private fun <T> decodeJson(
    encoded: String,
    label: String,
    serializer: kotlinx.serialization.KSerializer<T>,
): T {
    val json = try {
        String(Base64Url.decode(encoded), StandardCharsets.UTF_8)
    } catch (error: Exception) {
        throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, "The $label payload is not valid base64url.", error)
    }
    return try {
        SyncKitJson.instance.decodeFromString(serializer, json)
    } catch (error: Exception) {
        throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, "The $label payload is not valid JSON.", error)
    }
}

private fun normalizeDatasetFile(file: SharingDatasetFileV1): SharingDatasetFileV1 {
    if (file.datasetId.isBlank() || file.fileId.isBlank()) {
        throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, "A dataset file id must be a non-empty string.")
    }
    if (file.role == SharingRole.OWNER) {
        throw SyncKitError(SyncKitErrorCode.COMPATIBILITY, "A dataset file has an unsupported role: owner.")
    }
    return file
}

private fun appendQueryParams(landingUrl: String, params: Map<String, String>): String {
    val uri = URI(landingUrl)
    val query = linkedMapOf<String, String>()
    uri.rawQuery?.split("&")?.forEach { pair ->
        val parts = pair.split("=", limit = 2)
        if (parts.isNotEmpty() && parts[0].isNotBlank()) {
            query[parts[0]] = parts.getOrNull(1)
                ?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) }
                .orEmpty()
        }
    }
    query.putAll(params)
    val queryString = query.entries.joinToString("&") { (key, value) ->
        "$key=${URLEncoder.encode(value, StandardCharsets.UTF_8.name())}"
    }
    val path = uri.rawPath.orEmpty()
    val fragment = uri.rawFragment?.let { "#$it" }.orEmpty()
    return "${uri.scheme}://${uri.authority}$path?$queryString$fragment"
}

private fun parseQuery(input: String): Map<String, String> {
    val raw = when {
        input.startsWith("?") -> input.drop(1)
        "://" in input -> URI(input).rawQuery.orEmpty()
        else -> input
    }
    if (raw.isBlank()) return emptyMap()
    return raw.split("&").mapNotNull { pair ->
        val parts = pair.split("=", limit = 2)
        if (parts[0].isBlank()) null else {
            parts[0] to parts.getOrNull(1)
                ?.let { URLDecoder.decode(it, StandardCharsets.UTF_8.name()) }
                .orEmpty()
        }
    }.toMap()
}
