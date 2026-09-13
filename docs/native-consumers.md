# Native consumer guidance

`@keyneom/sync-kit` is a TypeScript package. Android apps use the sibling
Maven artifact `com.keyneom:sync-kit-android` for private v1 snapshots. Both
consume the same wire format and `fixtures/v1/` vectors.

## What is portable

The following behavior must be identical in TypeScript, Kotlin, and any future
native ports:

- unpadded RFC 4648 base64url;
- HKDF-SHA-256 with the profile's exact UTF-8 `info`;
- AES-256-GCM with a 12-byte nonce, 128-bit tag, and exact UTF-8 AAD;
- ciphertext followed by the GCM tag in the envelope's `ciphertext` field;
- profile-specific gzip behavior;
- exact envelope fields, filenames, RP IDs, and 32-byte passkey PRF inputs.

Use `fixtures/v1/` as the conformance suite. Do not generate platform-specific
expected ciphertext from random inputs and call that compatibility.

## Android

Published module: `android/synckit` → `com.keyneom:sync-kit-android`.

See [android-library.md](./android-library.md) for install and API shape.

Reference consumer: EasyBC (`easy-bc/android`), which depends on the library
via Gradle `includeBuild` and keeps only app-owned types (payload schema,
merge, Room persistence, Google Sign-In).

The library implements:

- Android Credential Manager for passkey PRF;
- HTTP Drive `appDataFolder` store;
- an in-memory derived-key session cleared by the app's lifecycle policy;
- `SnapshotSyncController` matching the npm `/snapshot` controller.

It is intentionally not emulated through a webview.

Shared backups ship on Android in `com.keyneom:sync-kit-android` alongside the
npm `/sharing` package. Both must consume `fixtures/sharing-v1/` before a
cross-platform sharing release.

### Picker grant handoff

Android cannot run the Google Picker. To grant `drive.file` access to files the
app did not create — a folder shared from another account, or a dataset created
on the web — hand off to a web page that runs the Picker.

**Why this works.** `drive.file` grants are keyed to the **Cloud project**, not
to an individual OAuth client. That is precisely what Picker's `setAppId`
expresses: it takes the project *number*, which is why
`GoogleDriveFolderPicker` names the option `cloudProjectNumber`. A grant made in
a browser under the web client is therefore visible to the Android client in the
same project, and to any other device signed into the same Google account.
Access follows the account and the project, not the device.

**Do not use SAF for this.** A SAF grant is a URI permission held by one app
install on one device. It authorizes nothing at the Drive API and crosses to no
other device, so it cannot substitute for a Picker grant — Drive returns 404 for
a file the grant does not cover.

**No return channel is required.** The grant *is* the shared state. Once the
user completes the Picker, the Android client enumerates exactly what it has
been granted with `listAccessibleSyncKitDatasets` (npm
`/stores/google-drive/sharing`; Kotlin
`com.keyneom.synckit.stores.listAccessibleSyncKitDatasets`). Do not build a
fileId hand-back from the grant page into the app: it duplicates a shipped
function and introduces a channel that can disagree with Drive.

**Launching the page.** Four details decide whether the handoff works at all,
and each one fails silently. Reference implementation: EasyBC's
`android/app/src/main/java/com/easybc/planner/util/GrantBrowser.kt`.

1. **A full browser tab, not a Custom Tab.** Google Identity Services' popup
   token flow breaks inside a Custom Tab — the popup replaces the page and the
   token never reaches the opener. Launch `ACTION_VIEW` with an explicit
   package.
2. **Resolve the browser with a neutral URL.** An app that owns the App Link for
   its own web origin receives its own unaddressed `ACTION_VIEW` intents, so
   resolving the grant URL returns the app itself. Probe with an unrelated
   `https://` URL.
3. **Exclude your own package and `android`.** The latter is the system
   disambiguation activity, not a browser. `CustomTabsClient.getPackageName` is
   a reasonable fallback for *discovering* a package — still launched as a plain
   tab.
4. **Fall back when nothing resolves.** Offer the link for the user to copy and
   open manually rather than failing silently.

Live OAuth and Picker validation against real Google remains a consumer release
gate. None of this is proven by unit tests.

### Sharing parity gate

Before claiming native sharing compatibility:

1. Kotlin unit tests verify and decrypt the sharing-v1 fixture (not only the
   standalone Java verifier).
2. `SharedBackupController` completes invite → response → accept → decrypt in
   mocked transport tests.
3. `SharingSyncCheckpoint` JSON matches the npm schema (`npm run parity:sharing:check`).
4. Live Drive smoke test passes on at least one platform.

See [background-notifications.md](./background-notifications.md) for Android-first
background detection.

## React Native and other JavaScript-native runtimes

Implement `CryptoBackend<K>` using the runtime's native crypto library, then
pass it to the v1 envelope helpers. `K` can remain an opaque native key handle.
Passkey, authorization, and cloud-store implementations should be separate
adapters; browser adapters depend on browser credential and identity APIs.

## Tauri and Keynote

Keynote's SQLite entities and binary attachments should not be serialized into
the snapshot controller. A future Keynote sync layer can use:

- `/core` provider contracts;
- `/crypto` with a Rust or WebCrypto backend;
- `GoogleDriveAppDataStore` for a fixed encrypted manifest and
  content-addressed encrypted blobs.

Google authorization should use the system browser with Authorization Code +
PKCE and a supported loopback or deep-link redirect. Do not use the Google web
token client in the Tauri webview.

## Cross-platform release gate

Before changing a writer version or cryptographic constant:

1. add a deterministic, synthetic fixture;
2. read it in every active platform implementation (npm tests and
   `android/synckit` unit tests);
3. run `npm run parity:check` so JS and Kotlin emit identical deterministic
   reports and cross-decrypt compressed envelopes;
4. install the packed library artifact into consumers;
5. stage writer-version changes only after all deployed readers support them.
