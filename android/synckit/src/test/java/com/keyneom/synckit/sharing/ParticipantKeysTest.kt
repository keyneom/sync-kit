package com.keyneom.synckit.sharing

import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.SyncKitJson
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ParticipantKeysTest {
    private val app = "participant-keys-app"
    private val dataset = "vault"
    private val codec = object : SharedBackupCodec<JsonElement> {
        override fun serialize(value: JsonElement): JsonElement = value
        override fun parse(value: JsonElement): JsonElement = value
    }

    private fun payload(label: String): JsonElement = buildJsonObject { put("secret", label) }

    private fun inputs(envelope: SharedBackupEnvelopeV1) =
        sharedBackupParticipants(envelope).map {
            SharedBackupParticipantInput(
                publicKey = SharingPublicKeyV1(
                    keyId = it.keyId,
                    encryptionAlgorithm = it.encryptionAlgorithm,
                    encryptionPublicKey = it.encryptionPublicKey,
                    signatureAlgorithm = it.signatureAlgorithm,
                    signingPublicKey = it.signingPublicKey,
                ),
                role = it.role,
                accepted = it.accepted,
            )
        }

    private fun write(
        author: SharingIdentity,
        previous: SharedBackupEnvelopeV1?,
        label: String,
        participants: List<SharedBackupParticipantInput>? = null,
        participantKeys: SharedBackupParticipantKeyChanges? = null,
        appId: String = app,
        backupId: String = dataset,
    ): SharedBackupEnvelopeV1 = SharingCrypto.createSharedBackupEnvelopeV1(
        payload(label),
        codec,
        author,
        CreateSharedBackupEnvelopeInput(
            appId = appId,
            backupId = backupId,
            participants = participants ?: inputs(previous!!),
            previous = previous,
            participantKeys = participantKeys,
        ),
    )

    private class Vault(
        val owner: SharingIdentity,
        val viewer: SharingIdentity,
        val writer: SharingIdentity,
        val genesis: SharedBackupEnvelopeV1,
        val enabled: SharedBackupEnvelopeV1,
    )

    private fun vault(): Vault {
        val owner = SharingCrypto.generateIdentity()
        val viewer = SharingCrypto.generateIdentity()
        val writer = SharingCrypto.generateIdentity()
        val genesis = write(
            owner,
            null,
            "v1",
            participants = listOf(
                SharedBackupParticipantInput(owner.publicKey, SharingRole.OWNER),
                SharedBackupParticipantInput(viewer.publicKey, SharingRole.VIEWER),
                SharedBackupParticipantInput(writer.publicKey, SharingRole.WRITER),
            ),
        )
        val enabled = write(owner, genesis, "v2", participantKeys = SharedBackupParticipantKeyChanges(policy = true))
        return Vault(owner, viewer, writer, genesis, enabled)
    }

    private class Recovery(val code: String, val identity: SharingIdentity, val addition: SharedBackupAdditionalKeyV1)

    private fun recoveryFor(principal: SharingIdentity, appId: String = app): Recovery {
        val code = ParticipantKeys.generateRecoveryCode()
        val recovery = ParticipantKeys.createRecoveryKey(appId, code)
        val addition = ParticipantKeys.createAddition(
            appId = appId,
            principalKeyId = principal.publicKey.keyId,
            authorizer = principal,
            key = recovery.identity,
            purpose = "recovery",
            sealedPrivateKeys = recovery.sealedPrivateKeys,
        )
        return Recovery(code, recovery.identity, addition)
    }

    private fun secret(envelope: SharedBackupEnvelopeV1, identity: SharingIdentity): String =
        SharingCrypto.decryptSharedBackupEnvelopeV1(envelope, codec, identity)
            .jsonObject.getValue("secret").jsonPrimitive.content

    private inline fun rejects(message: String, block: () -> Unit): SyncKitError {
        val error = try {
            block()
            null
        } catch (error: SyncKitError) {
            error
        }
        assertNotNull("expected a SyncKitError containing \"$message\"", error)
        assertTrue("\"${error!!.message}\" does not contain \"$message\"", error.message.orEmpty().contains(message))
        return error
    }

    // --- Protocol, written and read on Android ---------------------------------

    @Test
    fun leavesDatasetsThatNeverOptInOnSchemaVersionOne() {
        val vault = vault()
        assertEquals(1, vault.genesis.schemaVersion)
        assertEquals(2, vault.enabled.schemaVersion)
    }

    @Test
    fun viewerRecoversALostPasskeyFromTheCodeAndOneFile() {
        val vault = vault()
        val recovery = recoveryFor(vault.viewer)
        val withRecovery = write(
            vault.owner,
            vault.enabled,
            "v3",
            participantKeys = SharedBackupParticipantKeyChanges(add = listOf(recovery.addition)),
        )
        val offline = SharingCrypto.parseSharedBackupEnvelopeV1(
            SyncKitJson.instance.encodeToString(SharedBackupEnvelopeV1.serializer(), withRecovery),
        )
        val opened = ParticipantKeys.openRecoveryKeyFromEnvelope(recovery.code, offline)
        assertEquals("v3", secret(offline, opened.identity))

        val replacement = SharingCrypto.generateIdentity()
        val rotation = ParticipantKeys.createAuthorizedRotation(app, vault.viewer.publicKey.keyId, opened.identity, replacement)
        val rotated = write(vault.owner, withRecovery, "v4", participantKeys = SharedBackupParticipantKeyChanges(rotation = rotation))
        assertFalse(sharedBackupParticipants(rotated).any { it.keyId == vault.viewer.publicKey.keyId })
        assertEquals(
            SharingRole.VIEWER,
            sharedBackupParticipant(rotated, replacement.publicKey.keyId)?.role,
        )
        assertEquals(replacement.publicKey.keyId, sharedBackupAdditionalKeys(rotated).single().principalKeyId)
        assertEquals("v4", secret(rotated, replacement))
        rejects("not a participant") { secret(rotated, vault.viewer) }
    }

    @Test
    fun writerRecoversAloneWithTheRecoveryKeySigningTheAccessChange() {
        val vault = vault()
        val recovery = recoveryFor(vault.writer)
        val withRecovery = write(
            vault.writer,
            vault.enabled,
            "v3",
            participantKeys = SharedBackupParticipantKeyChanges(add = listOf(recovery.addition)),
        )
        val replacement = SharingCrypto.generateIdentity()
        val rotation = ParticipantKeys.createAuthorizedRotation(app, vault.writer.publicKey.keyId, recovery.identity, replacement)
        val rotated = write(
            replacement,
            withRecovery,
            "v4",
            participantKeys = SharedBackupParticipantKeyChanges(rotation = rotation, accessAuthor = recovery.identity),
        )
        assertEquals("v4", secret(rotated, replacement))
    }

    @Test
    fun ownerRecoversWithoutChangingTheTrustRoot() {
        val vault = vault()
        val recovery = recoveryFor(vault.owner)
        val withRecovery = write(
            vault.owner,
            vault.enabled,
            "v3",
            participantKeys = SharedBackupParticipantKeyChanges(add = listOf(recovery.addition)),
        )
        val replacement = SharingCrypto.generateIdentity()
        val rotation = ParticipantKeys.createAuthorizedRotation(app, vault.owner.publicKey.keyId, recovery.identity, replacement)
        val rotated = write(
            replacement,
            withRecovery,
            "v4",
            participantKeys = SharedBackupParticipantKeyChanges(rotation = rotation, accessAuthor = recovery.identity),
        )
        assertEquals(
            replacement.publicKey.keyId,
            sharedBackupParticipants(rotated).single { it.role == SharingRole.OWNER }.keyId,
        )
        SharingCrypto.verifySharedBackupEnvelopeV1(
            rotated,
            VerifySharedBackupOptions(trustedOwnerKeyId = vault.owner.publicKey.keyId),
        )
    }

    @Test
    fun removesOwnKeyAfterARotationAndNeverReAddsIt() {
        val vault = vault()
        val recovery = recoveryFor(vault.viewer)
        val withRecovery = write(
            vault.owner,
            vault.enabled,
            "v3",
            participantKeys = SharedBackupParticipantKeyChanges(add = listOf(recovery.addition)),
        )
        val replacement = SharingCrypto.generateIdentity()
        val rotated = write(
            vault.owner,
            withRecovery,
            "v4",
            participantKeys = SharedBackupParticipantKeyChanges(
                rotation = ParticipantKeys.createAuthorizedRotation(app, vault.viewer.publicKey.keyId, recovery.identity, replacement),
            ),
        )
        // Built from the key as originally added; the rotation has since moved it.
        val removal = ParticipantKeys.createRemoval(app, replacement, recovery.addition)
        val removed = write(
            vault.owner,
            rotated,
            "v5",
            participantKeys = SharedBackupParticipantKeyChanges(remove = listOf(ParticipantKeyRemoval.Signed(removal))),
        )
        assertTrue(sharedBackupAdditionalKeys(removed).isEmpty())
        rejects("cannot be re-added") {
            write(vault.owner, removed, "v6", participantKeys = SharedBackupParticipantKeyChanges(add = listOf(recovery.addition)))
        }
    }

    @Test
    fun turningThePolicyOffRemovesEveryKeyAndOrdinaryWritesKeepThem() {
        val vault = vault()
        val recovery = recoveryFor(vault.viewer)
        val withRecovery = write(
            vault.owner,
            vault.enabled,
            "v3",
            participantKeys = SharedBackupParticipantKeyChanges(add = listOf(recovery.addition)),
        )
        val ordinary = write(vault.writer, withRecovery, "v4")
        assertEquals(withRecovery.accessControl, ordinary.accessControl)
        assertEquals("v4", secret(ordinary, recovery.identity))
        val disabled = write(vault.owner, ordinary, "v5", participantKeys = SharedBackupParticipantKeyChanges(policy = false))
        assertTrue(sharedBackupAdditionalKeys(disabled).isEmpty())
        assertEquals(2, disabled.schemaVersion)
    }

    @Test
    fun rejectsEveryUnauthorizedChange() {
        val vault = vault()
        val recovery = recoveryFor(vault.viewer)
        rejects("owner or admin") {
            write(vault.writer, vault.genesis, "x", participantKeys = SharedBackupParticipantKeyChanges(policy = true))
        }
        rejects("does not allow additional") {
            write(vault.owner, vault.genesis, "x", participantKeys = SharedBackupParticipantKeyChanges(add = listOf(recovery.addition)))
        }
        val forged = ParticipantKeys.createAddition(
            appId = app,
            principalKeyId = vault.viewer.publicKey.keyId,
            authorizer = vault.owner,
            key = SharingCrypto.generateIdentity(),
            purpose = "recovery",
        )
        rejects("not authorized by its participant") {
            write(vault.owner, vault.enabled, "x", participantKeys = SharedBackupParticipantKeyChanges(add = listOf(forged)))
        }
        val otherSealed = ParticipantKeys.createRecoveryKey(app, ParticipantKeys.generateRecoveryCode()).sealedPrivateKeys
        rejects("not authorized by its participant") {
            write(
                vault.owner,
                vault.enabled,
                "x",
                participantKeys = SharedBackupParticipantKeyChanges(add = listOf(recovery.addition.copy(sealedPrivateKeys = otherSealed))),
            )
        }
        val withRecovery = write(
            vault.owner,
            vault.enabled,
            "v3",
            participantKeys = SharedBackupParticipantKeyChanges(add = listOf(recovery.addition)),
        )
        rejects("key's own participant") {
            write(
                vault.writer,
                withRecovery,
                "x",
                participantKeys = SharedBackupParticipantKeyChanges(
                    remove = listOf(ParticipantKeyRemoval.ByAdministrator(recovery.addition.keyId)),
                ),
            )
        }
        val hijack = ParticipantKeys.createAuthorizedRotation(
            app,
            vault.writer.publicKey.keyId,
            recovery.identity,
            SharingCrypto.generateIdentity(),
        )
        rejects("authorized key rotation is not valid") {
            write(vault.owner, withRecovery, "x", participantKeys = SharedBackupParticipantKeyChanges(rotation = hijack))
        }
        // A writer carrying a rotation of the owner's key, authorized by the viewer's recovery key.
        val ownerHijack = ParticipantKeys.createAuthorizedRotation(
            app,
            vault.owner.publicKey.keyId,
            recovery.identity,
            SharingCrypto.generateIdentity(),
        )
        rejects("authorized key rotation is not valid") {
            write(vault.writer, withRecovery, "x", participantKeys = SharedBackupParticipantKeyChanges(rotation = ownerHijack))
        }
        rejects("not allowed to write") { write(recovery.identity, withRecovery, "x") }
    }

    @Test
    fun recoveryCodesRoundTripAndReportTypos() {
        val code = ParticipantKeys.generateRecoveryCode()
        assertTrue(Regex("^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){6}$").matches(code))
        assertEquals(16, ParticipantKeys.parseRecoveryCode(code).size)
        assertTrue(ParticipantKeys.isRecoveryCodeWellFormed(code.lowercase().replace("-", " ")))
        val flipped = code.substring(0, 5) + (if (code[5] == 'A') 'B' else 'A') + code.substring(6)
        rejects("typo") { ParticipantKeys.parseRecoveryCode(flipped) }
        val error = rejects("not a recovery code") { ParticipantKeys.parseRecoveryCode("correct horse battery staple") }
        assertEquals(SyncKitErrorCode.KEY, error.code)
    }

    // --- Cross-platform: the web package wrote it, Android reads it -----------

    private val fixture: JsonObject by lazy {
        val stream = checkNotNull(javaClass.classLoader?.getResourceAsStream("sharing-v1/participant-keys.json")) {
            "Missing sharing-v1/participant-keys.json test resource."
        }
        SyncKitJson.instance.parseToJsonElement(stream.bufferedReader().use { it.readText() }).jsonObject
    }

    private fun fixtureEnvelope(name: String): SharedBackupEnvelopeV1 =
        SharingCrypto.parseSharedBackupEnvelopeV1(
            fixture.getValue("envelopes").jsonObject.getValue(name).toString(),
        )

    private fun fixtureIdentity(name: String): SharingIdentity {
        val entry = fixture.getValue(name).jsonObject
        val keys = entry.getValue("privateKeys").jsonObject
        return SharingEcKeys.identityFromPrivateKeyD(
            Base64Url.decode(keys.getValue("encryption").jsonObject.getValue("d").jsonPrimitive.content),
            Base64Url.decode(keys.getValue("signing").jsonObject.getValue("d").jsonPrimitive.content),
            SyncKitJson.instance.decodeFromJsonElement(SharingPublicKeyV1.serializer(), entry.getValue("publicKey")),
        )
    }

    private fun expected(name: String): String =
        fixture.getValue("expected").jsonObject.getValue("payloads").jsonObject.getValue(name)
            .jsonObject.getValue("items").toString()

    private fun items(envelope: SharedBackupEnvelopeV1, identity: SharingIdentity): String =
        SharingCrypto.decryptSharedBackupEnvelopeV1(envelope, codec, identity)
            .jsonObject.getValue("items").toString()

    @Test
    fun verifiesAndDecryptsEveryWebWrittenRevision() {
        val owner = fixtureIdentity("owner")
        val trust = VerifySharedBackupOptions(trustedOwnerKeyId = owner.publicKey.keyId)
        for (name in listOf("genesis", "enabled", "withRecovery", "rotated", "removed")) {
            val envelope = fixtureEnvelope(name)
            SharingCrypto.verifySharedBackupEnvelopeV1(envelope, trust)
            assertEquals(name, if (name == "genesis") 1 else 2, envelope.schemaVersion)
            assertEquals(name, expected(name), items(envelope, owner))
        }
    }

    @Test
    fun opensAWebSealedRecoveryKeyAndFollowsItsRotation() {
        val code = fixture.getValue("recoveryCode").jsonPrimitive.content
        val withRecovery = fixtureEnvelope("withRecovery")
        val opened = ParticipantKeys.openRecoveryKeyFromEnvelope(code, withRecovery)
        assertEquals(fixture.getValue("recoveryKeyId").jsonPrimitive.content, opened.identity.publicKey.keyId)
        assertEquals(expected("withRecovery"), items(withRecovery, opened.identity))

        val viewer = fixtureIdentity("viewer")
        val replacement = fixtureIdentity("replacement")
        val rotated = fixtureEnvelope("rotated")
        assertEquals(null, sharedBackupParticipant(rotated, viewer.publicKey.keyId))
        assertEquals(replacement.publicKey.keyId, sharedBackupAdditionalKeys(rotated).single().principalKeyId)
        assertEquals(expected("rotated"), items(rotated, replacement))
        assertEquals(expected("rotated"), items(rotated, opened.identity))

        val removed = fixtureEnvelope("removed")
        assertTrue(sharedBackupAdditionalKeys(removed).isEmpty())
        rejects("not a participant") { items(removed, opened.identity) }
    }

    @Test
    fun rejectsATamperedWebWrittenAddition() {
        val envelope = fixture.getValue("envelopes").jsonObject.getValue("withRecovery").jsonObject
        val tampered = envelope.toString().replace(
            sharedBackupAdditionalKeys(fixtureEnvelope("withRecovery")).single().addition,
            sharedBackupAdditionalKeys(fixtureEnvelope("withRecovery")).single().possession,
        )
        rejects("") {
            SharingCrypto.verifySharedBackupEnvelopeV1(SharingCrypto.parseSharedBackupEnvelopeV1(tampered))
        }
    }

    // --- Cross-platform: Android writes it, the web package reads it ----------

    /**
     * Writes an Android-built history for scripts/check-recovery-parity.sh,
     * which verifies it with the web package and opens the Android-sealed recovery
     * key there. A no-op unless PARTICIPANT_KEYS_OUTPUT is set.
     */
    @Test
    fun writesAnAndroidBuiltHistoryForTheWebToVerify() {
        val output = System.getenv("PARTICIPANT_KEYS_OUTPUT") ?: return
        val owner = SharingCrypto.generateIdentity()
        val viewer = SharingCrypto.generateIdentity()
        val replacement = SharingCrypto.generateIdentity()
        val appId = "fixture-app"
        val backupId = "participant-keys-kotlin"
        val genesis = write(
            owner,
            null,
            "genesis",
            participants = listOf(
                SharedBackupParticipantInput(owner.publicKey, SharingRole.OWNER),
                SharedBackupParticipantInput(viewer.publicKey, SharingRole.VIEWER),
            ),
            appId = appId,
            backupId = backupId,
        )
        val enabled = write(
            owner, genesis, "enabled",
            participantKeys = SharedBackupParticipantKeyChanges(policy = true),
            appId = appId, backupId = backupId,
        )
        val recovery = recoveryFor(viewer, appId)
        val withRecovery = write(
            owner, enabled, "with-recovery",
            participantKeys = SharedBackupParticipantKeyChanges(add = listOf(recovery.addition)),
            appId = appId, backupId = backupId,
        )
        val rotated = write(
            owner, withRecovery, "rotated",
            participantKeys = SharedBackupParticipantKeyChanges(
                rotation = ParticipantKeys.createAuthorizedRotation(appId, viewer.publicKey.keyId, recovery.identity, replacement),
            ),
            appId = appId, backupId = backupId,
        )
        val encode = { envelope: SharedBackupEnvelopeV1 ->
            SyncKitJson.instance.encodeToJsonElement(SharedBackupEnvelopeV1.serializer(), envelope)
        }
        val report = buildJsonObject {
            put("ownerKeyId", owner.publicKey.keyId)
            put("recoveryCode", recovery.code)
            put("recoveryKeyId", recovery.identity.publicKey.keyId)
            put("replacementKeyId", replacement.publicKey.keyId)
            put(
                "envelopes",
                buildJsonObject {
                    put("withRecovery", encode(withRecovery))
                    put("rotated", encode(rotated))
                },
            )
            put(
                "secrets",
                buildJsonObject {
                    put("withRecovery", JsonPrimitive("with-recovery"))
                    put("rotated", JsonPrimitive("rotated"))
                },
            )
        }
        File(output).writeText(report.toString())
    }
}
