# @keyneom/sync-kit

Compatibility-preserving encrypted application-data synchronization for web,
desktop, JavaScript-native, and native protocol consumers.

The package extracts the behavior already implemented by EasyBC and Family
Chores. It does not own application schemas, merge policy, persistence, UI, or
lifecycle policy.

## Status

Version `0.1.0` is implemented and configured as a public MIT-licensed package.

The tests in this repository cover frozen compatibility vectors, mocked
browser providers, package orchestration, and installation/imports from the
packed tarball. They do not install this package into EasyBC, Family Chores, or
Keynote.

As separate baseline checks, the existing sync-related tests in EasyBC and
Family Chores were run unchanged from those repositories. No consumer
repository was modified. Consumer migrations and their post-migration test
runs remain separate release gates.

## Install

```sh
npm install @keyneom/sync-kit
```

The package has no runtime dependencies and is ESM-only.

## Subpath exports

```ts
import {
  easyBcV1Profile,
  familyChoresV1Profile,
} from "@keyneom/sync-kit/crypto";
import { createSnapshotSync } from "@keyneom/sync-kit/snapshot";
import { createWebPasskeyProvider } from "@keyneom/sync-kit/keys/web-passkey";
import { GoogleWebAuthorizationProvider } from "@keyneom/sync-kit/auth/google-web";
import {
  GoogleDriveAppDataStore,
  GoogleDriveSnapshotStore,
} from "@keyneom/sync-kit/stores/google-drive";
```

Available exports:

- `/core` — provider contracts and standardized errors
- `/crypto` — v1 envelopes, profiles, AES-GCM/HKDF backends, base64url,
  optional gzip, and canonical JSON/AAD helpers
- `/snapshot` — serialized snapshot synchronization
- `/snapshot/lifecycle` — opt-in browser lifecycle binding
- `/keys/web-passkey` — WebAuthn PRF keys with exact credential selection,
  unlock coalescing, raw-secret zeroing, and explicit cache clearing
- `/auth/google-web` — Google Identity Services with memory-only token reuse,
  expiry skew, request coalescing, and explicit invalidation
- `/stores/google-drive` — low-level `appDataFolder` objects plus a typed
  snapshot wrapper

The root, `/core`, `/crypto`, and `/snapshot` expose no browser adapter.
Browser globals and script loading are used only after an explicit browser
subpath method is called.

## Snapshot integration

Applications provide their own codec and state callbacks:

```ts
const controller = createSnapshotSync({
  appId: "family-chores",
  codec: {
    serialize: (value) => value,
    parse: parseFamilyChoresPayload,
    merge: mergeFamilyChoresPayloads,
    fingerprint: stableFamilyChoresFingerprint,
    updatedAt: (value) => value.exportedAt,
  },
  envelopeCrypto,
  keyProvider,
  authorizationProvider,
  cloudStore,
  readLocal,
  applyMerged,
  envelopeUpdatedAt: (envelope) => envelope.updatedAt,
});

await controller.setup();
await controller.sync("change");
controller.lock();
```

The controller serializes cloud operations, queues at most one real local
change behind active work, ignores foreground feedback during OAuth/passkey
operations, and avoids encryption/upload when the merged stable fingerprint
matches the remote value.

## Native applications

The wire protocol is the native compatibility boundary; the browser adapter is
not.

- EasyBC Android's Kotlin implementation reads the same v1 AES-GCM/HKDF/gzip
  fixtures as this package.
- React Native and other JavaScript-native runtimes can inject a
  `CryptoBackend<K>` backed by platform crypto.
- Kotlin and Swift applications implement the small key, authorization, store,
  and crypto contracts natively while consuming the shared fixtures.
- Tauri applications can use `/core`, `/crypto`, and the low-level Google Drive
  object store, but should perform OAuth in the system browser through
  Authorization Code + PKCE.

See [native consumer guidance](docs/native-consumers.md) and the exact
[v1 compatibility contract](docs/compatibility-v1.md).

## Compatibility and isolation

The explicit profiles preserve both applications' v1 filenames, AAD, HKDF
labels, compression behavior, and passkey names. V1 readers remain separate
because their cryptographic contexts are intentionally incompatible.

The Drive snapshot wrapper rejects the wrong `appId` before making a request.
WebAuthn unlock requests include only the envelope's exact credential ID and
reject the wrong RP ID before opening passkey UI.

Do not change EasyBC's writer to v2 until Android can read v2. V2 envelopes and
desktop-specific authorization/key adapters remain deferred.

## Security boundary

The package:

- keeps OAuth tokens and derived keys in memory only;
- makes AES-GCM keys non-extractable in the WebCrypto backend;
- zeroes raw PRF output after derivation;
- clears key and authorization caches on explicit lock/delete;
- authenticates each v1 ciphertext with its application-specific AAD.

Applications still control provider configuration, metadata exposure, merge
correctness, local persistence, lifecycle timing, and access to the JavaScript
runtime. The package does not make a compromised application private.

## Development

```sh
npm install
npm run check
```

`npm run check` verifies deterministic fixtures, lint, types, tests, build
output, packed contents, npm installation, pnpm installation, and every
documented subpath import from the installed tarball.

The extraction plan and phase gates are in
[docs/implementation-plan.md](docs/implementation-plan.md) and
[docs/execution-checklist.md](docs/execution-checklist.md).
