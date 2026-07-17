package com.keyneom.synckit.sharing

import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class LinkExchangeTest {
    private fun fixtureRoot() = SyncKitJson.instance.parseToJsonElement(
        javaClass.classLoader
            ?.getResourceAsStream("sharing-v1/link-exchange.json")
            ?.use { it.readBytes().toString(Charsets.UTF_8) }
            ?: error("Missing sharing-v1/link-exchange.json test resource."),
    ).jsonObject

    /** A WebCrypto-encoded invitation + response must decode and verify on Android. */
    @Test
    fun decodesAndVerifiesWebCryptoEncodedPayloads() {
        val root = fixtureRoot()
        val expected = root["expected"]!!.jsonObject

        val invitation = decodeSharingInvitationV1(root["encodedInvitation"]!!.jsonPrimitive.content)
        val verifiedInvitation = SharingCrypto.verifySharingInvitationV1(invitation)
        assertEquals(expected["ownerKeyId"]!!.jsonPrimitive.content, verifiedInvitation.owner.keyId)
        assertEquals(expected["exchangeId"]!!.jsonPrimitive.content, verifiedInvitation.exchangeId)

        val response = decodeSharingPublicKeyResponseV1(root["encodedResponse"]!!.jsonPrimitive.content)
        val verifiedResponse = SharingCrypto.verifySharingPublicKeyResponseV1(response)
        assertEquals(expected["recipientKeyId"]!!.jsonPrimitive.content, verifiedResponse.keyId)
    }

    /** The WebCrypto-built join + response links must parse on Android. */
    @Test
    fun parsesWebCryptoJoinAndResponseLinks() {
        val root = fixtureRoot()
        val expected = root["expected"]!!.jsonObject

        val join = parseSharingJoinLinkV1(root["joinLink"]!!.jsonPrimitive.content)
        assertNotNull(join)
        assertEquals(expected["appFolderId"]!!.jsonPrimitive.content, join!!.invitation.appFolderId)
        assertEquals(2, join.files.size)
        assertEquals("primary", join.files[0].datasetId)
        assertEquals("file-primary", join.files[0].fileId)
        assertEquals(SharingRole.VIEWER, join.files[0].role)
        assertEquals(SharingRole.WRITER, join.files[1].role)
        SharingCrypto.verifySharingInvitationV1(join.invitation)
        assertEquals(join.files, verifySharingLinkDatasetFilesV1(join.invitation, join.files))

        val responseLink = parseSharingResponseLinkV1(root["responseLink"]!!.jsonPrimitive.content)
        assertNotNull(responseLink)
        assertEquals(
            expected["recipientKeyId"]!!.jsonPrimitive.content,
            responseLink!!.response.keyId,
        )
    }

    /** Android's own encode/decode is internally consistent. */
    @Test
    fun kotlinEncodeDecodeRoundTrips() {
        val root = fixtureRoot()
        val invitation = decodeSharingInvitationV1(root["encodedInvitation"]!!.jsonPrimitive.content)
        assertEquals(invitation, decodeSharingInvitationV1(encodeSharingInvitationV1(invitation)))
    }
}
