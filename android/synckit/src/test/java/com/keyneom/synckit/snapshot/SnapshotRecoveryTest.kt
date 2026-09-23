package com.keyneom.synckit.snapshot

import android.app.Activity
import com.keyneom.synckit.core.Authorization
import com.keyneom.synckit.core.AuthorizationProvider
import com.keyneom.synckit.core.CloudStore
import com.keyneom.synckit.core.CreatedKey
import com.keyneom.synckit.core.KeyProvider
import com.keyneom.synckit.core.SnapshotOperation
import com.keyneom.synckit.core.StoredEnvelope
import com.keyneom.synckit.core.SyncCodec
import com.keyneom.synckit.core.SyncKitError
import com.keyneom.synckit.core.SyncKitErrorCode
import com.keyneom.synckit.core.SyncOutcome
import com.keyneom.synckit.core.SyncReason
import com.keyneom.synckit.crypto.Base64Url
import com.keyneom.synckit.crypto.PasskeyProfile
import com.keyneom.synckit.crypto.RecoveryCodes
import com.keyneom.synckit.crypto.SyncEnvelopeV1
import com.keyneom.synckit.crypto.SyncKitJson
import com.keyneom.synckit.crypto.V1CompatibilityProfile
import com.keyneom.synckit.crypto.V1Compression
import com.keyneom.synckit.crypto.V1EnvelopeCrypto
import com.keyneom.synckit.crypto.V1KeyMetadata
import java.io.File
import java.security.SecureRandom
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SnapshotRecoveryTest {
    private val random = SecureRandom()
    private fun bytes(length: Int) = ByteArray(length).also(random::nextBytes)

    private fun profile(
        appId: String = "recovery-app",
        readVersions: List<Int> = listOf(1),
        writeVersion: Int = 1,
        aad: String = "recovery-app-v1",
        hkdfInfo: String = "recovery-app content key",
    ) = V1CompatibilityProfile(
        appId = appId,
        filename = "$appId.json",
        aad = aad,
        hkdfInfo = hkdfInfo,
        compression = V1Compression.GZIP_IF_SMALLER,
        passkey = PasskeyProfile("Recovery App", "user", "User"),
        readVersions = readVersions,
        writeVersion = writeVersion,
    )

    /** JSON `{items, updatedAt}`, merged as a sorted union — the same shape the web tests use. */
    private val codec = object : SyncCodec<JsonObject> {
        override fun serialize(value: JsonObject): ByteArray = value.toString().toByteArray(Charsets.UTF_8)
        override fun parse(bytes: ByteArray): JsonObject =
            SyncKitJson.instance.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        override fun merge(local: JsonObject, remote: JsonObject): JsonObject =
            snapshot((items(local) + items(remote)).distinct().sorted(), maxOf(updatedAt(local), updatedAt(remote)))
        override fun fingerprint(value: JsonObject): String = items(value).sorted().joinToString(",")
        override fun updatedAt(value: JsonObject): String = value.getValue("updatedAt").jsonPrimitive.content
    }

    private fun items(value: JsonObject) = value.getValue("items").jsonArray.map { it.jsonPrimitive.content }
    private fun updatedAt(value: JsonObject) = value.getValue("updatedAt").jsonPrimitive.content
    private fun snapshot(items: List<String>, updatedAt: String) = buildJsonObject {
        put("items", JsonArray(items.map(::JsonPrimitive)))
        put("updatedAt", updatedAt)
    }
    private fun at(minute: Int) = "2026-09-23T00:%02d:00.000Z".format(minute)

    /** Keeps each credential's PRF secret; clearing it simulates losing the passkey. */
    private class Passkeys(private val crypto: V1EnvelopeCrypto<JsonObject>) : KeyProvider {
        val authenticator = mutableMapOf<String, ByteArray>()
        private var created = 0

        override suspend fun create(activity: Activity, appId: String): CreatedKey {
            val credentialId = "credential-${++created}"
            val secret = crypto.randomBytes(32).also { authenticator[credentialId] = it }
            val metadata = V1KeyMetadata(credentialId, "recovery.example", crypto.randomBytes(32), crypto.randomBytes(32))
            return CreatedKey(metadata, crypto.deriveContentKey(secret, metadata.kdfSalt))
        }

        override suspend fun unlock(activity: Activity, envelope: SyncEnvelopeV1): ByteArray {
            val secret = authenticator[envelope.credentialId]
                ?: throw SyncKitError(SyncKitErrorCode.KEY, "This passkey is not available on this device.")
            return crypto.deriveContentKey(secret, Base64Url.decode(envelope.kdfSalt))
        }

        override fun clear() = Unit
    }

    private class Cloud : CloudStore {
        var envelope: SyncEnvelopeV1? = null

        override suspend fun find(appId: String, authorization: Authorization): StoredEnvelope? =
            envelope?.let { StoredEnvelope("file", it) }

        override suspend fun write(
            appId: String,
            envelope: SyncEnvelopeV1,
            authorization: Authorization,
            existingId: String?,
        ): String {
            this.envelope = envelope
            return "file"
        }

        override suspend fun delete(appId: String, fileId: String, authorization: Authorization) {
            envelope = null
        }
    }

    private class Device(val controller: SnapshotSyncController<JsonObject>, val crypto: V1EnvelopeCrypto<JsonObject>) {
        var local: JsonObject? = null
    }

    private fun device(profile: V1CompatibilityProfile, cloud: Cloud, keys: Passkeys, local: JsonObject): Device {
        val crypto = V1EnvelopeCrypto(profile, codec)
        lateinit var created: Device
        val controller = SnapshotSyncController(
            SnapshotSyncOptions(
                appId = profile.appId,
                codec = codec,
                envelopeCrypto = crypto,
                keyProvider = keys,
                authorizationProvider = object : AuthorizationProvider {
                    override suspend fun authorize() = Authorization("token")
                },
                cloudStore = cloud,
                readLocal = { created.local ?: local },
                applyMerged = { created.local = it },
                activity = { Activity() },
            ),
        )
        created = Device(controller, crypto)
        return created
    }

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

    @Test
    fun leavesV1ExactlyAsItWasUnlessAProfileOptsIn() = runBlocking {
        val appProfile = profile()
        val cloud = Cloud()
        val phone = device(appProfile, cloud, Passkeys(V1EnvelopeCrypto(appProfile, codec)), snapshot(listOf("a"), at(1)))
        phone.controller.setup()
        val envelope = checkNotNull(cloud.envelope)
        assertEquals(1, envelope.schemaVersion)
        assertNull(envelope.appId)
        assertNull(envelope.passkeyKey)
        val encoded = SyncKitJson.instance.encodeToString(SyncEnvelopeV1.serializer(), envelope)
        assertTrue(listOf("appId", "contentSalt", "passkeyKey", "recoveryKey").none { encoded.contains("\"$it\"") })
        val error = rejects("readVersions") { phone.controller.setRecoveryCode(RecoveryCodes.generate()) }
        assertEquals(SyncKitErrorCode.CONFIGURATION, error.code)
    }

    @Test
    fun recoversALostPasskeyOnANewDeviceWithTheCodeAlone() = runBlocking {
        val appProfile = profile(readVersions = listOf(1, 2))
        val cloud = Cloud()
        val keys = Passkeys(V1EnvelopeCrypto(appProfile, codec))
        val phone = device(appProfile, cloud, keys, snapshot(listOf("a"), at(1)))
        phone.controller.setup()
        val code = RecoveryCodes.generate()
        phone.controller.setRecoveryCode(code)
        assertEquals(2, cloud.envelope?.schemaVersion)
        assertEquals("recovery-app", cloud.envelope?.appId)

        phone.local = snapshot(listOf("a", "b"), at(2))
        val lockBefore = cloud.envelope?.recoveryKey
        phone.controller.sync(SyncReason.CHANGE)
        assertEquals(2, cloud.envelope?.schemaVersion)
        assertEquals(lockBefore, cloud.envelope?.recoveryKey)

        keys.authenticator.clear()
        val newDevice = device(appProfile, cloud, keys, snapshot(listOf("c"), at(3)))
        rejects("not available") { newDevice.controller.sync(SyncReason.FOREGROUND) }
        val recovered = newDevice.controller.recover(code)
        assertEquals(SnapshotOperation.RECOVER, recovered.operation)
        assertEquals(SyncOutcome.RECOVERED, recovered.outcome)
        assertEquals(listOf("a", "b", "c"), items(checkNotNull(recovered.value)))
        assertEquals(SyncOutcome.UNCHANGED, newDevice.controller.sync(SyncReason.FOREGROUND).outcome)
        assertEquals(listOf("a", "b", "c"), items(newDevice.crypto.decryptWithRecoveryCode(checkNotNull(cloud.envelope), code)))
    }

    @Test
    fun distinguishesATypoFromAWrongCodeAndRemovesTheCode(): Unit = runBlocking {
        val appProfile = profile(readVersions = listOf(1, 2))
        val cloud = Cloud()
        val phone = device(appProfile, cloud, Passkeys(V1EnvelopeCrypto(appProfile, codec)), snapshot(listOf("a"), at(1)))
        phone.controller.setup()
        val code = RecoveryCodes.generate()
        phone.controller.setRecoveryCode(code)
        val envelope = checkNotNull(cloud.envelope)
        val typo = code.substring(0, 5) + (if (code[5] == 'A') 'B' else 'A') + code.substring(6)
        rejects("typo") { phone.crypto.decryptWithRecoveryCode(envelope, typo) }
        rejects("does not unlock") { phone.crypto.decryptWithRecoveryCode(envelope, RecoveryCodes.generate()) }
        phone.controller.setRecoveryCode(null)
        assertNull(cloud.envelope?.recoveryKey)
        rejects("no recovery code") { phone.crypto.decryptWithRecoveryCode(checkNotNull(cloud.envelope), code) }
    }

    @Test
    fun migratesExplicitlyAndReversiblyAndV1DropsTheCode() = runBlocking {
        val appProfile = profile(readVersions = listOf(1, 2))
        val cloud = Cloud()
        val keys = Passkeys(V1EnvelopeCrypto(appProfile, codec))
        val phone = device(appProfile, cloud, keys, snapshot(listOf("a"), at(1)))
        phone.controller.setup()
        phone.controller.setRecoveryCode(RecoveryCodes.generate())
        phone.controller.migrateVersion(1)
        assertEquals(1, cloud.envelope?.schemaVersion)
        assertNull(cloud.envelope?.recoveryKey)
        val old = device(profile(), cloud, keys, snapshot(emptyList(), at(0)))
        assertEquals(listOf("a"), items(checkNotNull(old.controller.sync(SyncReason.FOREGROUND).value)))
        phone.controller.migrateVersion(2)
        assertEquals(2, cloud.envelope?.schemaVersion)
    }

    @Test
    fun refusesV2WithoutOptingInAndAuthenticatesTheHeaderAndAppId(): Unit = runBlocking {
        val appProfile = profile(readVersions = listOf(1, 2), writeVersion = 2)
        val cloud = Cloud()
        val keys = Passkeys(V1EnvelopeCrypto(appProfile, codec))
        device(appProfile, cloud, keys, snapshot(listOf("a"), at(1))).controller.setup()
        val envelope = checkNotNull(cloud.envelope)
        assertEquals(2, envelope.schemaVersion)
        rejects("readVersions") { device(profile(), cloud, keys, snapshot(emptyList(), at(0))).controller.sync(SyncReason.FOREGROUND) }
        val key = keys.unlock(Activity(), envelope)
        val crypto = V1EnvelopeCrypto(appProfile, codec)
        rejects("could not be decrypted") { crypto.decrypt(envelope.copy(updatedAt = at(9)), key) }
        rejects("belongs to recovery-app") {
            V1EnvelopeCrypto(profile(appId = "another-app", readVersions = listOf(1, 2)), codec).decrypt(envelope, key)
        }
    }

    @Test
    fun validatesVersionsInTheProfile() {
        for ((reads, write) in listOf(listOf(2) to 2, listOf(1) to 2, listOf(1, 3) to 1)) {
            val error = try {
                profile(readVersions = reads, writeVersion = write)
                null
            } catch (error: IllegalArgumentException) {
                error
            }
            assertNotNull("readVersions=$reads writeVersion=$write should be rejected", error)
        }
    }

    // --- Cross-platform: the web package wrote it, Android reads it ---------

    private val fixture: JsonObject by lazy {
        val stream = checkNotNull(javaClass.classLoader?.getResourceAsStream("v2/snapshot-recovery.json")) {
            "Missing v2/snapshot-recovery.json test resource."
        }
        SyncKitJson.instance.parseToJsonElement(stream.bufferedReader().use { it.readText() }).jsonObject
    }

    private fun fixtureProfile(readVersions: List<Int> = listOf(1, 2)): V1CompatibilityProfile {
        val input = fixture.getValue("profile").jsonObject
        return profile(
            appId = input.getValue("appId").jsonPrimitive.content,
            aad = input.getValue("aad").jsonPrimitive.content,
            hkdfInfo = input.getValue("hkdfInfo").jsonPrimitive.content,
            readVersions = readVersions,
        )
    }

    private fun fixtureEnvelope(name: String): SyncEnvelopeV1 =
        V1EnvelopeCrypto(fixtureProfile(), codec).parseEnvelope(
            fixture.getValue("envelopes").jsonObject.getValue(name).toString(),
        )

    private fun fixtureKey(crypto: V1EnvelopeCrypto<JsonObject>, passkey: String): ByteArray {
        val entry = fixture.getValue("passkeys").jsonObject.getValue(passkey).jsonObject
        return crypto.deriveContentKey(
            Base64Url.decode(entry.getValue("prfSecret").jsonPrimitive.content),
            Base64Url.decode(entry.getValue("kdfSalt").jsonPrimitive.content),
        )
    }

    private fun expected(name: String): List<String> =
        items(fixture.getValue("expected").jsonObject.getValue(name).jsonObject)

    @Test
    fun decryptsEveryWebWrittenSnapshotWithItsPasskeyAndItsCode() {
        val crypto = V1EnvelopeCrypto(fixtureProfile(), codec)
        val code = fixture.getValue("recoveryCode").jsonPrimitive.content
        val original = fixtureKey(crypto, "original")
        val replacement = fixtureKey(crypto, "replacement")
        assertEquals(expected("plain"), items(crypto.decrypt(fixtureEnvelope("plain"), original)))
        assertEquals(expected("withRecovery"), items(crypto.decrypt(fixtureEnvelope("withRecovery"), original)))
        assertEquals(expected("withRecovery"), items(crypto.decryptWithRecoveryCode(fixtureEnvelope("withRecovery"), code)))
        // After recovery the snapshot opens with the new passkey and still with the code.
        assertEquals(expected("relocked"), items(crypto.decrypt(fixtureEnvelope("relocked"), replacement)))
        assertEquals(expected("relocked"), items(crypto.decryptWithRecoveryCode(fixtureEnvelope("relocked"), code)))
        rejects("could not open") { crypto.decrypt(fixtureEnvelope("relocked"), original) }
        val migrated = fixtureEnvelope("migrated")
        assertEquals(1, migrated.schemaVersion)
        assertEquals(expected("migrated"), items(V1EnvelopeCrypto(fixtureProfile(listOf(1)), codec).decrypt(migrated, original)))
    }

    @Test
    fun refusesAWebWrittenV2SnapshotWhenTheProfileReadsOnlyV1() {
        rejects("readVersions") {
            V1EnvelopeCrypto(fixtureProfile(listOf(1)), codec).parseEnvelope(
                fixture.getValue("envelopes").jsonObject.getValue("plain").toString(),
            )
        }
    }

    // --- Cross-platform: Android writes it, the web package reads it --------

    /**
     * Writes Android-built v2 snapshots for scripts/check-recovery-parity.sh,
     * which opens them with the web package — with the passkey secret and with
     * the Android-sealed recovery code. A no-op unless SNAPSHOT_RECOVERY_OUTPUT
     * is set.
     */
    @Test
    fun writesAndroidBuiltSnapshotsForTheWebToOpen() {
        val output = System.getenv("SNAPSHOT_RECOVERY_OUTPUT") ?: return
        val appProfile = profile(appId = "fixture-recovery-kotlin", readVersions = listOf(1, 2), writeVersion = 2)
        val crypto = V1EnvelopeCrypto(appProfile, codec)
        val secret = bytes(32)
        val metadata = V1KeyMetadata("credential-kotlin", "fixture.example", bytes(32), bytes(32))
        val key = crypto.deriveContentKey(secret, metadata.kdfSalt)
        val code = RecoveryCodes.generate()
        val value = snapshot(listOf("kotlin", "shared"), at(5))
        val withRecovery = crypto.setRecoveryCode(crypto.encrypt(value, key, metadata), key, code)
        val report = buildJsonObject {
            put(
                "profile",
                buildJsonObject {
                    put("appId", appProfile.appId)
                    put("aad", appProfile.aad)
                    put("hkdfInfo", appProfile.hkdfInfo)
                },
            )
            put("prfSecret", Base64Url.encode(secret))
            put("recoveryCode", code)
            put("envelope", SyncKitJson.instance.encodeToJsonElement(SyncEnvelopeV1.serializer(), withRecovery))
            put("expected", value)
        }
        File(output).writeText(report.toString())
    }
}
