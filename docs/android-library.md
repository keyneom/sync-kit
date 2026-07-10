# Android library (`com.keyneom:sync-kit-android`)

Primary native target for **shared encrypted backups** and **background change
detection**. Private v1 snapshot sync is also included, matching the npm
package’s `/crypto`, `/snapshot`, and appData store surface.

The npm `/sharing` package remains the reference implementation for browser
deployments. Android aims for protocol and checkpoint parity where platform
APIs allow.

## Coordinates

| Field | Value |
| --- | --- |
| Group | `com.keyneom` |
| Artifact | `sync-kit-android` |
| Version | release tag (`0.2.0-rc.11`); npm publication is independent |
| Module | `android/synckit` |
| Registry | [GitHub Packages](https://github.com/keyneom/sync-kit/packages) (`https://maven.pkg.github.com/keyneom/sync-kit`) |

## Install

### GitHub Packages (recommended for apps)

GitHub Packages uses your existing GitHub account — no Maven Central or
third-party registry signup.

1. Create a [personal access token](https://github.com/settings/tokens) with
   **`read:packages`** (and `repo` if the package repo is private).
2. Add credentials to `~/.gradle/gradle.properties` (never commit these):

```properties
gpr.user=YOUR_GITHUB_USERNAME
gpr.key=ghp_...
```

3. Add the repository and dependency:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://maven.pkg.github.com/keyneom/sync-kit")
            credentials {
                username = providers.gradleProperty("gpr.user").get()
                password = providers.gradleProperty("gpr.key").get()
            }
        }
    }
}

// app/build.gradle.kts
implementation("com.keyneom:sync-kit-android:0.2.0-rc.11")
```

In CI, set `GITHUB_ACTOR` and `GITHUB_TOKEN` instead of `gpr.*` properties.

### Composite build (development)

When sync-kit is checked out beside your app:

```kotlin
// settings.gradle.kts
includeBuild("../sync-kit/android") {
    dependencySubstitution {
        substitute(module("com.keyneom:sync-kit-android"))
            .using(project(":synckit"))
    }
}
```

## What apps provide

Same split as the npm package:

- **Profile** — `V1CompatibilityProfile` (appId, filename, AAD, HKDF info,
  compression, passkey display names)
- **Codec** — application schema serialize / parse / merge / fingerprint
- **Authorization** — `AuthorizationProvider` with refresh-token policy for
  background polling (auth code + PKCE recommended)
- **Activity** — Credential Manager passkey ceremonies
- **Local state** — profile index, reminder index, notification channels
- **WorkManager scheduling** — periodic `SharingSyncWorker` enqueue

See [consumer-responsibilities.md](./consumer-responsibilities.md) and
[background-notifications.md](./background-notifications.md).

## Library packages

### Private snapshot (shipped)

| Type | Role |
| --- | --- |
| `V1EnvelopeCrypto` | AES-GCM, HKDF, gzip-if-smaller |
| `SnapshotSyncController` | setup / enable / sync / reset / delete |
| `AndroidPasskeyKeyProvider` | Credential Manager PRF |
| `GoogleDriveAppDataStore` | legacy `appDataFolder` store |

### Shared backups (shipped)

| Type | Role |
| --- | --- |
| `sharing.*` | Protocol parsers, P-256 ECDH/ECDSA, invitations, envelopes |
| `sharing.SharedBackupController` | Headless invite / accept / sync / reconcile |
| `stores.GoogleDriveFileStore` | normal Drive `drive.file` operations |
| `stores.GoogleDriveSharedBackupTransport` | app folder, exchanges, datasets |
| `sharing.SharingChangeDetector` | metadata-only Tier A polling |
| `sharing.work.SharingSyncWorker` | WorkManager skeleton (detect only) |

### Application-owned

- Notification channels and copy
- Tier B local reminders (`AlarmManager`, local DB)
- OAuth refresh token storage (EncryptedSharedPreferences / AccountManager)
- Folder picker / join deep-link intents
- Profile switcher UI

## Background sync

Android is the full-feature path:

```kotlin
// App schedules periodically (e.g. every 30–60 minutes)
WorkManager.getInstance(context).enqueueUniquePeriodicWork(
    "sharing-poll-$profileId",
    ExistingPeriodicWorkPolicy.KEEP,
    PeriodicWorkRequestBuilder<SharingSyncWorker>(30, TimeUnit.MINUTES).build(),
)

// Worker returns events; app shows notifications — never accepts keys in background
```

Web Tier A is limited to ~one hour access-token lifetime; see
[background-notifications.md](./background-notifications.md).

## Parity

- Private v1: `fixtures/v1/` + `npm run parity:check`
- Sharing v1: `fixtures/sharing-v1/` + Kotlin unit tests + `npm run parity:sharing:check`

## Tests

```sh
cd android
./gradlew :synckit:test
```

Cross-platform private snapshot parity:

```sh
npm run parity:check
```
