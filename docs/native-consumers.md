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

Shared backups are not on Android yet.

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
