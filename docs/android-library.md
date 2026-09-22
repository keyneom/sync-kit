# Android library (`com.keyneom:sync-kit-android`)

Primary native target for **shared encrypted backups** and **background change
detection**. Private v1 snapshot sync is also included, matching the npm
package’s `/crypto`, `/snapshot`, and appData store surface.

The npm `/sharing` package remains the reference implementation for browser
deployments. Android aims for protocol and checkpoint parity where platform
APIs allow.

## One passkey, both platforms

**Android derives the same passkey PRF secret as the browser.** One envelope
serves both platforms: a backup sealed under a passkey in Chrome is opened and
rewritten by the phone, and vice versa. `AndroidPasskeyKeyProvider` does this
today and EasyBC ships it in exactly that configuration
(`android/app/src/main/java/com/easybc/planner/sync/EasyBcSync.kt`).

**The invariant is that every platform can write every envelope.** The failure
is not a second envelope; it is a platform that can only rewrite one of them.
When Android cannot open the passkey envelope, a second envelope sealed under a
different secret — a printed recovery code, a device-local key — quietly becomes
that platform's everyday key. Each side then refreshes only its own copy, the
two diverge on the first edit, and a later reseal on one side locks the other
out of its own backup. That sequence has cost a real user their cloud data.

A recovery envelope is legitimate, and for some products necessary: a lost
passkey with no recovery path is lost data, which may be acceptable for a
planner and not for a password manager. Keep it as a *recovery* path — written
by whichever device syncs, refreshed from the same state as every other copy —
and never as the only key one platform can reach.

If Credential Manager appears unable to return a PRF secret on Android, check
[Digital Asset Links](#digital-asset-links-required-for-passkey-unlock) before
concluding the platform cannot do it. A missing asset link is reported as "no
usable credential", which is indistinguishable from the user having no passkey.

## Coordinates

| Field | Value |
| --- | --- |
| Group | `com.keyneom` |
| Artifact | `sync-kit-android` |
| Version | release tag; always equal to the npm version |
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
implementation("com.keyneom:sync-kit-android:0.4.4")
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
| `sharing.SharedBackupController` | Headless invite / accept / sync / reconcile / dual-signed ownership transfer |
| `sharing.SharingControlDataset` | Signed control directory and hard-cutover migration ledger |
| `sharing.createSharingControlCodec` | Deterministic event-union codec matching npm `/sharing/control` |
| `stores.GoogleDriveFileStore` | normal Drive `drive.file` operations |
| `stores.GoogleDriveSharedBackupTransport` | app folder, exchanges, datasets |
| `sharing.SharingChangeDetector` | metadata-only Tier A polling |
| `sharing.work.SharingSyncWorker` | WorkManager skeleton (detect only) |
| `sharing.SharingAccountBindings` | TS-compatible challenge, Credential Manager assertion, WebAuthn/JWT verification |
| `sharing.CachingGoogleJwksProvider` | bounded Google JWKS cache with unknown-`kid` refresh |

### Application-owned

- Notification channels and copy
- Tier B local reminders (`AlarmManager`, local DB)
- OAuth refresh token storage (EncryptedSharedPreferences / AccountManager)
- Folder picker / join deep-link intents
- Profile switcher UI
- RP ID, exact web/APK origin allowlist, Google server/web OAuth client ID,
  and Google sign-in UI

## Account binding

Pass the consumer-owned RP/origin/audience policy into the library and wire
the existing controller callbacks to `SharingAccountBindings.createBackendless`
and `SharingAccountBindings.verify`. The Google acquisition callback must
request an ID token for the server/web OAuth client ID and use the supplied
challenge as its nonce; an Android-package OAuth client ID is not automatically
the correct audience.

Android Credential Manager assertions use an origin of the form
`android:apk-key-hash:<unpadded-base64url-sha256-certificate>`. Build exact
values with `androidApkKeyHashOrigin`, `androidApkKeyHashOriginFromSha256`, or
`androidApkKeyHashOriginFromHexSha256`. Production configuration normally
allows the production web origin and release signing certificate. Add a debug
certificate origin only to development/test configuration. Matching is exact;
wildcards, prefixes, package names, and substring matching are not supported.

Configure `AndroidPasskeyKeyProvider(registrationOrigins = ...)` when creating
protected sharing identities. It validates registration client data,
authenticator flags, RP hash, credential ID, and the ES256/P-256 COSE key before
persisting `credentialPublicKey`. Existing records without that field cannot
recover it from a later assertion. Unlock the old record, register a replacement
passkey, and call `ProtectedSharingIdentityCrypto.rewrapWithReplacementCredential`;
persist the returned record atomically only after the replacement registration
succeeds. The sharing key ID is preserved.

The library's general minimum remains API 26, but consumer passkey flows must
gate Credential Manager passkey use to Android 9 / API 28 or newer.

### Digital Asset Links (required for passkey unlock)

Credential Manager will not release a passkey registered for a **web** RP ID to
an Android app unless that domain's Digital Asset Links file names the app. This
is a hard precondition: without it the provider cannot work at all, and the
failure does not say so.

Serve `https://<rp-id>/.well-known/assetlinks.json`:

```json
[
  {
    "relation": [
      "delegate_permission/common.handle_all_urls",
      "delegate_permission/common.get_login_creds"
    ],
    "target": {
      "namespace": "android_app",
      "package_name": "com.example.app",
      "sha256_cert_fingerprints": [
        "AB:CD:EF:...:12:34"
      ]
    }
  }
]
```

Four things decide whether this works:

1. **`delegate_permission/common.get_login_creds` is the relation that matters.**
   It is what lets the app hold credentials saved for that domain — including
   the passkey the app's own backup is sealed with. Omitting it as a
   least-privilege measure disables passkey unlock entirely.
2. **The two relations are independent.** `handle_all_urls` governs App Links
   only. An app can have fully verified App Links and no passkey access, and
   `pm get-app-links` reports a healthy state throughout, so it is not a useful
   check for this.
3. **It is served from the RP ID domain root, which is usually a different
   repository.** For a GitHub Pages project site the RP ID is the user or
   organization domain, so the file lives in that domain's root repository — not
   alongside the app, and not alongside the project site.
4. **The fingerprint identifies the signing certificate, not the package.** A
   re-signed build is a different app and every passkey stops resolving. List
   every certificate you ship under — debug, release, and Play App Signing if
   enabled. Play App Signing re-signs by default, which breaks *both* relations
   at once: App Link verification and passkey access fail together, and nothing
   in either failure names the certificate.

There is no `adb` query that reports `get_login_creds`. The only check is
attempting a ceremony on a device — see the validation gate below.

Asset links cannot be verified by unit tests. See the validation gate below.

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
- Account binding: shared golden challenge plus TS/Kotlin signature, JWKS,
  COSE/JWK, origin, controller, and migration tests

## Tests

```sh
cd android
./gradlew :synckit:test
```

Cross-platform private snapshot parity:

```sh
npm run parity:check
```

Unit tests do not prove Android Credential Manager behavior. Before enabling
`requireAccountBinding` in a consumer, validate registration and assertion on a
real API 28+ device, including Digital Asset Links, release APK origin, Google
nonce/audience behavior, and a real web-to-Android two-account exchange.
