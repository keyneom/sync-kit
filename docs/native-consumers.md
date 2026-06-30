# Native consumer guidance

`sync-kit` is a TypeScript package, but its compatibility contract is
not browser-specific. Native applications use the same envelope and provider
contracts with platform implementations.

## What is portable

The following behavior must be identical in TypeScript, Kotlin, Swift, Rust,
and JavaScript-native runtimes:

- unpadded RFC 4648 base64url;
- HKDF-SHA-256 with the profile's exact UTF-8 `info`;
- AES-256-GCM with a 12-byte nonce, 128-bit tag, and exact UTF-8 AAD;
- ciphertext followed by the GCM tag in the envelope's `ciphertext` field;
- profile-specific gzip behavior;
- exact envelope fields, filenames, RP IDs, and passkey PRF inputs.

Use `fixtures/v1/` as the conformance suite. Do not generate platform-specific
expected ciphertext from random inputs and call that compatibility.

## Android

EasyBC is the current Android reference implementation:

```text
android/app/src/main/java/com/easybc/planner/sync/SyncCrypto.kt
android/app/src/main/java/com/easybc/planner/sync/PasskeyPrfClient.kt
android/app/src/main/java/com/easybc/planner/sync/GoogleDriveSyncClient.kt
android/app/src/test/java/com/easybc/planner/sync/SyncCryptoTest.kt
```

Its `AES/GCM/NoPadding`, RFC 5869 HKDF implementation, `GZIPInputStream`, and
Credential Manager PRF requests consume the shared EasyBC fixture. The native
RP ID is fixed to `keyneom.github.io`, and unlock requests include exactly one
credential ID.

A reusable Android adapter should implement the core contracts with:

- Android Credential Manager for passkey PRF;
- Google Identity authorization for the Drive app-data scope;
- an HTTP Drive `appDataFolder` store;
- an in-memory derived-key session cleared by the app's lifecycle policy.

That adapter is intentionally not emulated through a webview.

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
2. read it in every active platform implementation;
3. write it in at least one implementation and read it in every other;
4. install the packed library artifact into consumers;
5. stage writer-version changes only after all deployed readers support them.
