# @keyneom/sync-kit

Compatibility-preserving encrypted application-data synchronization for web,
desktop, JavaScript-native, and native protocol consumers.

The package extracts the behavior already implemented by EasyBC and Family
Chores. It does not own application schemas, merge policy, persistence, UI, or
lifecycle policy.

## Backend-independent by design

A primary package objective is to let a static frontend provide encrypted sync
and multi-user sharing without an application-owned trusted backend. The
complete interactive flow must be implementable with browser cryptography and
passkeys, Google Identity Services, and Google Drive:

- no server-held client secret or refresh token;
- no application database, certificate signer, or authorization service;
- no server required to encrypt, decrypt, invite, accept, reconcile access, or
  publish a signed revision.

Google remains the OAuth, identity, and storage provider. Participant keys,
signed access-control history, and the pinned owner key remain the
cryptographic authority. An optional backend adapter may add unattended jobs,
notifications, or operational automation, but package correctness and
interoperability must never depend on one.

Backendless browser deployments operate while the app is open and may need
user interaction when OAuth access expires or a passkey ceremony is required.
That limitation must not be hidden by broad Drive scopes or by making a
backend mandatory.

## Status

Version `0.1.1` was published to npm on 2026-06-30. It removes the
application-specific runtime presets from `0.1.0` and keeps compatibility
profiles consumer-owned.

The current worktree is the unpublished `0.2.0-rc.0` sharing release
candidate. Publication remains gated on live Google validation and one
external consumer integration.

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
  createV1EnvelopeCrypto,
  createWebCryptoBackend,
  defineV1CompatibilityProfile,
} from "@keyneom/sync-kit/crypto";
import { createSnapshotSync } from "@keyneom/sync-kit/snapshot";
import { createWebPasskeyProvider } from "@keyneom/sync-kit/keys/web-passkey";
import { GoogleWebAuthorizationProvider } from "@keyneom/sync-kit/auth/google-web";
import {
  GoogleDriveAppDataStore,
  GoogleDriveSnapshotStore,
} from "@keyneom/sync-kit/stores/google-drive";
```

Applications define their own profile:

```ts
const profile = defineV1CompatibilityProfile({
  appId: "my-notes",
  filename: "my-notes-sync-v1.json",
  aad: "my-notes-sync-envelope-v1",
  hkdfInfo: "my-notes-content-key-v1",
  compression: "gzip-if-smaller",
  passkey: {
    rpName: "My Notes",
    userName: "encrypted-sync",
    userDisplayName: "My Notes encrypted sync",
    algorithm: -7,
    residentKey: "required",
    userVerification: "required",
    timeoutMs: 60_000,
  },
});

const envelopeCrypto = createV1EnvelopeCrypto(
  profile,
  appCodec,
  createWebCryptoBackend(),
);
```

The package does not export profiles for EasyBC, Family Chores, or any other
consumer. Profile values are application configuration. Application data
models, parsing, migration, merge, and fingerprints remain in `appCodec`, so a
model change does not require a `sync-kit` release.

Available exports:

- `/core` — provider contracts and standardized errors
- `/crypto` — v1 envelopes, profiles, AES-GCM/HKDF backends, base64url,
  optional gzip, and canonical JSON/AAD helpers
- `/snapshot` — serialized snapshot synchronization
- `/snapshot/lifecycle` — opt-in browser lifecycle binding
- `/sharing` — browser-independent shared-backup protocol types, validation,
  roles, invitations, and signed multi-recipient envelopes
- `/sharing/web-crypto` — P-256 identities, ECDH key grants, signed revisions,
  invitation/key-response proofs, and decryption
- `/sharing/controller` — headless multi-dataset orchestration, owner pinning,
  serialized writes, exchange processing, roles, and revocation
- `/sharing/web-passkey` — passkey-encrypted sharing identities with
  non-extractable runtime keys and optional IndexedDB ciphertext storage
- `/sharing/account-binding` — backendless Google ID-token and WebAuthn
  challenge binding, signature verification, and account provenance
- `/keys/web-passkey` — WebAuthn PRF keys with exact credential selection,
  unlock coalescing, raw-secret zeroing, and explicit cache clearing
- `/auth/google-web` — Google Identity Services with memory-only token reuse,
  expiry skew, request coalescing, and explicit invalidation
- `/auth/google-web/identity` — uncached nonce-bound Google ID tokens for
  account-binding exchanges
- `/stores/google-drive` — low-level `appDataFolder` objects, a typed snapshot
  wrapper, and normal-Drive folder/per-file stores
- `/stores/google-drive/sharing` — managed app/exchange folders, conditional
  dataset writes, provenance checks, and per-dataset permissions
- `/stores/google-drive/picker` — explicit folder Picker and Drive Open-with
  state parsing

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

- **Android:** `com.keyneom:sync-kit-android` (module `android/synckit`) provides
  private v1 snapshot crypto, `SnapshotSyncController`, Drive `appDataFolder`
  storage, and Credential Manager passkey PRF — the same contracts as the npm
  `/crypto`, `/snapshot`, and appData store paths. See
  [android-library.md](docs/android-library.md).
- Shared backups (`/sharing`) are TypeScript-only for now.
- React Native and other JavaScript-native runtimes can inject a
  `CryptoBackend<K>` backed by platform crypto.
- Tauri applications can use `/core`, `/crypto`, and the low-level Google Drive
  object store, but should perform OAuth in the system browser through
  Authorization Code + PKCE.

See [native consumer guidance](docs/native-consumers.md) and the exact
[v1 compatibility contract](docs/compatibility-v1.md).

## Shared encrypted backups

The experimental sharing surface encrypts each revision with a fresh content
key, wraps that key to every participant's ECDH public key, and accepts writes
only when an owner/admin/writer signs the complete revision. Viewers receive a
decryption grant but are not authorized revision signers.

Sharing follows the package-wide backend-independent objective above. A static
frontend can execute the protocol directly against Google Drive; an
application-owned server is neither a trust root nor a deployment requirement.

Shared files use normal Google Drive storage with the per-file `drive.file`
scope. A recipient can select the shared app folder once through Google Picker,
after which the app reuses its ID for app-created children; broad access to
Drive is not required. `appDataFolder` files cannot be shared.

New integrations can use `GoogleDriveFileSnapshotStore`, which defaults to an
app-owned top-level folder:

```text
Sync Kit - <appId>/
  <consumer filename>
```

The folder name can be overridden. A selected parent folder is optional rather
than part of the default flow. Existing v1 consumers continue using
`GoogleDriveSnapshotStore` and `appDataFolder` until they explicitly migrate.

For shared data, the default policy makes the app folder readable to all app
participants, makes its `exchanges/` child writable, and upgrades selected
participants to writer on individual dataset files. This exposes filenames,
metadata, and ciphertext to app participants while cryptographic grants control
decryption. Applications needing metadata isolation can instead use direct file
sharing or limited-access subfolders.

See the [protocol and threat model](docs/shared-backups.md) and
[authoritative implementation handoff](docs/sharing-implementation-handoff.md).
The phased gates remain in the
[sharing execution plan](docs/sharing-execution-plan.md). The crypto and
per-file transport, Picker, protected identity, account binding, signed
ancestry/fork policy, key rotation, and controller primitives are implemented.
The same sharing fixture is consumed by Java, and the packed package completes
an exchange/decryption smoke test. Live Google OAuth/Picker, Drive
conditional-write/permission validation, and adoption in an external consumer
remain release gates.

## Compatibility and isolation

Each application owns the profile that preserves its filename, AAD, HKDF
label, compression behavior, and passkey names. V1 readers remain separate
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
