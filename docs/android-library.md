# Android library (`com.keyneom:sync-kit-android`)

Private v1 snapshot sync for Android, matching the npm package’s
`/crypto`, `/snapshot`, `/keys/web-passkey`, and
`/stores/google-drive` (appData) surface.

Shared encrypted backups (`/sharing`) are **not** in this artifact yet.
They remain TypeScript-only until a separate Android sharing port.

## Coordinates

| Field | Value |
| --- | --- |
| Group | `com.keyneom` |
| Artifact | `sync-kit-android` |
| Version | same as npm (`0.2.0-rc.0` while unpublished) |
| Module | `android/synckit` |

## Install

From a composite build (development, as EasyBC does):

```kotlin
// settings.gradle.kts
includeBuild("../sync-kit/android") {
    dependencySubstitution {
        substitute(module("com.keyneom:sync-kit-android"))
            .using(project(":synckit"))
    }
}

// app/build.gradle.kts
implementation("com.keyneom:sync-kit-android:0.2.0-rc.0")
```

From Maven Local after `./gradlew :synckit:publishToMavenLocal` in
`android/`:

```kotlin
repositories { mavenLocal() }
implementation("com.keyneom:sync-kit-android:0.2.0-rc.0")
```

## What apps provide

Same split as the npm package:

- **Profile** — `V1CompatibilityProfile` (appId, filename, AAD, HKDF info,
  compression, passkey display names)
- **Codec** — `SyncCodec<T>` (`serialize` / `parse` / `merge` / `fingerprint` /
  `updatedAt`)
- **Authorization** — `AuthorizationProvider` that returns a Drive access token
- **Activity** — for Credential Manager passkey ceremonies
- **Local state** — `readLocal` / `applyMerged`

## Library pieces

| Type | Role |
| --- | --- |
| `V1EnvelopeCrypto` | AES-GCM, HKDF, gzip-if-smaller, 32-byte PRF input validation |
| `SnapshotSyncController` | setup / enable / sync / reset / delete, serialized ops, change dirty-flag |
| `AndroidPasskeyKeyProvider` | Credential Manager PRF + in-memory content-key cache |
| `GoogleDriveAppDataStore` | `appDataFolder` find / write / delete by profile filename |

## Parity notes

Private snapshot crypto and controller behavior match the npm package and the
frozen `fixtures/v1` EasyBC vectors. Android previously inlined the same logic
inside EasyBC; that code now lives here.

Not included (npm-only today):

- shared-backup protocol and controller
- normal-Drive `drive.file` sharing transport
- Google account-binding attestation
- web Picker / GIS token client (Android apps use Play Services auth)

## Tests

```sh
cd android
# requires ANDROID_HOME or android/local.properties sdk.dir
./gradlew :synckit:test
```

Cross-platform parity with the npm package (same content keys, fixture
summaries, fixed-nonce envelopes, rejection codes, plus mutual decrypt of
compressed peer envelopes):

```sh
npm run parity:check
```

That runs `scripts/check-js-kotlin-parity.sh`, which builds both reports and
diffs them. Gzip ciphertext may differ by platform; the script requires each
side to decrypt the other's compressed `peerChallenge` instead of byte-matching
those envelopes.
