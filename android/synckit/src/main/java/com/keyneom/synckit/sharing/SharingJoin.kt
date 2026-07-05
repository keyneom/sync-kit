package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

const val SHARING_JOIN_MARKER_PARAM = "sync-kit-join"
const val SHARING_JOIN_EXCHANGE_PARAM = "sync-kit-exchange"
const val SHARING_JOIN_FOLDER_PARAM = "sync-kit-folder"
const val SHARING_JOIN_SHORT_MARKER_PARAM = "sync"
const val SHARING_JOIN_SHORT_MARKER_VALUE = "join"
const val SHARING_JOIN_SHORT_EXCHANGE_PARAM = "exchange"
const val SHARING_JOIN_SHORT_FOLDER_PARAM = "folder"

data class SharingJoinParams(
    val appFolderId: String,
    val exchangeId: String? = null,
)

enum class SharingJoinParamStyle {
    SYNC_KIT,
    SHORT,
}

data class SharingJoinInvitationMatch(
    val invitationFileId: String,
    val invitation: SharingInvitationV1,
)

fun parseSharingJoinParams(input: String): SharingJoinParams? {
    val params = toSearchParams(input)
    val appFolderId = readJoinParam(
        params,
        listOf(SHARING_JOIN_FOLDER_PARAM, SHARING_JOIN_SHORT_FOLDER_PARAM),
    ) ?: return null
    if (!isJoinMarkerPresent(params)) return null
    val exchangeId = readJoinParam(
        params,
        listOf(SHARING_JOIN_EXCHANGE_PARAM, SHARING_JOIN_SHORT_EXCHANGE_PARAM),
    )
    return SharingJoinParams(appFolderId = appFolderId, exchangeId = exchangeId)
}

fun buildSharingJoinSearchParams(
    params: SharingJoinParams,
    style: SharingJoinParamStyle = SharingJoinParamStyle.SYNC_KIT,
): Map<String, String> {
    require(params.appFolderId.isNotBlank()) { "appFolderId must not be empty." }
    return buildMap {
        if (style == SharingJoinParamStyle.SHORT) {
            put(SHARING_JOIN_SHORT_MARKER_PARAM, SHARING_JOIN_SHORT_MARKER_VALUE)
            put(SHARING_JOIN_SHORT_FOLDER_PARAM, params.appFolderId)
            params.exchangeId?.trim()?.takeIf { it.isNotEmpty() }?.let {
                put(SHARING_JOIN_SHORT_EXCHANGE_PARAM, it)
            }
        } else {
            put(SHARING_JOIN_MARKER_PARAM, "1")
            put(SHARING_JOIN_FOLDER_PARAM, params.appFolderId)
            params.exchangeId?.trim()?.takeIf { it.isNotEmpty() }?.let {
                put(SHARING_JOIN_EXCHANGE_PARAM, it)
            }
        }
    }
}

fun appendSharingJoinParams(
    landingUrl: String,
    params: SharingJoinParams,
    style: SharingJoinParamStyle = SharingJoinParamStyle.SYNC_KIT,
): String {
    val uri = URI(landingUrl)
    val query = linkedMapOf<String, String>()
    uri.rawQuery?.split("&")?.forEach { pair ->
        val parts = pair.split("=", limit = 2)
        if (parts.isNotEmpty() && parts[0].isNotBlank()) {
            query[parts[0]] = parts.getOrNull(1)?.let {
                URLDecoder.decode(it, StandardCharsets.UTF_8.name())
            }.orEmpty()
        }
    }
    query.putAll(buildSharingJoinSearchParams(params, style))
    val queryString = query.entries.joinToString("&") { (key, value) ->
        "$key=${java.net.URLEncoder.encode(value, StandardCharsets.UTF_8.name())}"
    }
    val path = uri.rawPath.orEmpty()
    val fragment = uri.rawFragment?.let { "#$it" }.orEmpty()
    return "${uri.scheme}://${uri.authority}$path?$queryString$fragment"
}

fun formatSharingInviteEmailMessage(
    joinUrl: String,
    appDisplayName: String,
    intro: String? = null,
): String {
    require(joinUrl.isNotBlank()) { "joinUrl must not be empty." }
    require(appDisplayName.isNotBlank()) { "appDisplayName must not be empty." }
    val messageIntro = intro?.trim()?.takeIf { it.isNotEmpty() }
        ?: "You have been invited to share $appDisplayName data."
    return "$messageIntro\n\nOpen this link to join in $appDisplayName:\n${joinUrl.trim()}"
}

suspend fun findSharingJoinInvitation(
    transport: SharedBackupTransport,
    exchangeId: String,
): SharingJoinInvitationMatch? {
    require(exchangeId.isNotBlank()) { "exchangeId must not be empty." }
    val exchanges = transport.listExchanges(exchangeId = exchangeId, kind = "invitation")
    val invitationFile = exchanges.firstOrNull() ?: return null
    val invitation = transport.readInvitation(invitationFile.fileId)
    return SharingJoinInvitationMatch(
        invitationFileId = invitationFile.fileId,
        invitation = invitation,
    )
}

suspend fun resolveSharingJoinInvitation(
    transport: SharedBackupTransport,
    params: SharingJoinParams,
): SharingJoinInvitationMatch {
    val storage = transport.ensureStorage()
    if (storage.appFolderId != params.appFolderId) {
        throw SyncKitError(
            SyncKitErrorCode.CONFIGURATION,
            "The transport app folder does not match the join link.",
        )
    }
    params.exchangeId?.let { exchangeId ->
        return findSharingJoinInvitation(transport, exchangeId)
            ?: throw SyncKitError(
                SyncKitErrorCode.NOT_FOUND,
                "No invitation matches the join exchange ID.",
            )
    }
    val invitations = transport.listExchanges(kind = "invitation")
    if (invitations.isEmpty()) {
        throw SyncKitError(
            SyncKitErrorCode.NOT_FOUND,
            "No pending invitation was found in the shared app folder.",
        )
    }
    if (invitations.size > 1) {
        throw SyncKitError(
            SyncKitErrorCode.STATE,
            "Multiple pending invitations were found; include exchangeId in the join link.",
        )
    }
    val invitationFile = invitations.first()
    val invitation = transport.readInvitation(invitationFile.fileId)
    return SharingJoinInvitationMatch(
        invitationFileId = invitationFile.fileId,
        invitation = invitation,
    )
}

private fun toSearchParams(input: String): Map<String, String> {
    val raw = when {
        input.startsWith("?") -> input.drop(1)
        "://" in input -> URI(input).rawQuery.orEmpty()
        else -> input
    }
    if (raw.isBlank()) return emptyMap()
    return raw.split("&").mapNotNull { pair ->
        val parts = pair.split("=", limit = 2)
        if (parts[0].isBlank()) null else {
            parts[0] to parts.getOrNull(1)?.let {
                URLDecoder.decode(it, StandardCharsets.UTF_8.name())
            }.orEmpty()
        }
    }.toMap()
}

private fun isJoinMarkerPresent(params: Map<String, String>): Boolean =
    params[SHARING_JOIN_MARKER_PARAM] == "1" ||
        params[SHARING_JOIN_SHORT_MARKER_PARAM] == SHARING_JOIN_SHORT_MARKER_VALUE

private fun readJoinParam(params: Map<String, String>, keys: List<String>): String? {
    for (key in keys) {
        val value = params[key]?.trim()
        if (!value.isNullOrEmpty()) return value
    }
    return null
}
