# Implementation plan: extract `sync-kit`

This document is the implementation contract for the standalone
`/Users/micaelsanchez/repos/sync-kit` repository. It was moved from EasyBC on
2026-06-29 so extraction work can proceed without coupling the package history
to a consumer application.

Create one reusable npm package with subpath exports so applications import only
the capabilities they need. Treat the existing EasyBC and Family Chores
implementations as compatibility sources; do not redesign their persisted
formats during extraction.

## Package name and scope

Working repository name: **`sync-kit`**. Published npm package name:
**`@keyneom/sync-kit`**.

The capability-oriented `sync-kit` name is preferable to `private-sync`
because the package coordinates encryption, synchronization, key providers,
authorization, and storage providers. It also leaves room for providers other
than Google Drive and WebAuthn PRF without overstating a broad "secure" or
"private" guarantee.

Other reasonable candidates:

- `snapshot-sync` — precise for EasyBC and Family Chores, but too
  narrow for Keynote's manifest/blob model.
- `cipher-sync` — memorable, but makes the orchestration and provider
  adapters sound secondary.
- `secure-sync` — clear, but "secure" is a broad claim that is harder
  to define and defend.
- `sync-core` — provider-neutral, but sounds like only the low-level
  layer rather than the adapters and convenience API.

The repository is implemented locally at `/Users/micaelsanchez/repos/sync-kit`.
The public MIT-licensed package uses `@keyneom/sync-kit`. npm rejected the
unscoped `sync-kit` name because it is too similar to the existing `synckit`
package, so the owner scope is required by the registry. The scope does not
change the single-package architecture or subpath API.

## Package structure

```text
sync-kit
├── /core
├── /crypto
├── /snapshot
├── /keys/web-passkey
├── /auth/google-web
└── /stores/google-drive
```

Keep one package with subpath exports. The root and provider-neutral subpaths
must have no browser globals or import-time side effects. Browser-specific
code belongs only in explicit browser subpaths.

## Core interfaces

Use opaque key handles where possible so orchestration code never needs raw
passkey PRF output:

```ts
interface KeyProvider<E, K> {
  create(context: KeyCreationContext): Promise<CreatedKey<E, K>>;
  unlock(envelope: E): Promise<K>;
  clear(): void;
}

interface AuthorizationProvider {
  authorize(): Promise<Authorization>;
  clear(): void;
}

interface CloudStore<E> {
  find(appId: string): Promise<StoredEnvelope<E> | null>;
  write(envelope: E, existingId?: string): Promise<string>;
  delete?(fileId: string): Promise<void>;
}

interface SyncCodec<T> {
  serialize(value: T): unknown;
  parse(value: unknown): T;
  merge(local: T, remote: T): T;

  // Must ignore volatile metadata such as exportedAt. Used to prevent
  // sync loops and unnecessary cloud writes.
  fingerprint(value: T): string;
}
```

Provide `createSnapshotSync<T>()` as the convenience orchestration layer for
EasyBC and Family Chores. Applications supply their codec, merge behavior,
local-state reader, and merged-state application callback.

The returned controller should expose explicit operations and state:

```ts
interface SnapshotSyncController<T> {
  setup(): Promise<SyncResult<T>>;
  enable(): Promise<SyncResult<T>>;
  sync(reason: "startup" | "foreground" | "change" | "manual"): Promise<SyncResult<T>>;
  reset(): Promise<SyncResult<T>>;
  delete(): Promise<void>;
  lock(): void;
  operationInProgress(): boolean;
}
```

Do not install global `visibilitychange`, `pagehide`, or lifecycle listeners at
module import. Export optional lifecycle helpers or let each application call
`sync()` and `lock()` from its own lifecycle.

## Responsibility boundary

The package owns:

- AES-256-GCM encryption.
- HKDF-SHA-256 key derivation.
- Optional gzip-before-encryption when it reduces payload size.
- Versioned encrypted envelopes and a consumer-defined profile contract.
- Base64url encoding.
- WebAuthn PRF passkey creation/unlocking.
- Google Identity Services authorization.
- Short-lived, memory-only Google access-token reuse with expiry skew,
  concurrent-request coalescing, and invalidation after authorization failure.
- Google Drive `appDataFolder` reads/writes.
- Sync operation serialization and standardized errors.
- Coalescing concurrent passkey unlocks.
- Reentrancy rules: a real local change may queue behind an active sync, but
  OAuth/passkey visibility or foreground events must not create another sync.
- No-op detection: do not encrypt or upload when the merged stable fingerprint
  matches the remote payload.
- App-ID, provider, and envelope compatibility checks.
- Explicit session locking and memory-cache clearing.

Each application owns:

- Its compatibility profile values: application ID, filename, AAD, HKDF info,
  compression policy, and passkey display names.
- Its data schema and validation.
- Conflict resolution and tombstones.
- Stable fingerprint semantics, including exclusion of volatile fields.
- Local persistence.
- UI and status presentation.
- OAuth client configuration.
- Applying merged state.
- Choosing startup, foreground, debounce, and background-grace policies.
- Platform lifecycle integration.

Sharing adopters should also read
[consumer-responsibilities.md](consumer-responsibilities.md) for multi-profile
indexing, Drive folder naming, join deeplinks, and related boundaries beyond
this list.

## Session and authorization behavior

The default web behavior should support one interactive authorization/unlock
per active app session:

- Keep only a non-extractable derived `CryptoKey` in JavaScript memory.
- Zero raw PRF output immediately after deriving the content key.
- Never place keys or OAuth tokens in localStorage, sessionStorage, IndexedDB,
  cookies, logs, or serialized application state.
- Reuse a Google access token in memory only until its reported expiry, with a
  safety margin; clear it on HTTP 401, explicit lock, delete/disable, or session
  expiry.
- Clear the derived key and authorization cache on page/process termination or
  the application's configured background timeout.
- Serialize cloud operations so manual and automatic sync cannot race and
  overwrite each other.
- Ignore foreground/visibility events generated by an authorization or
  passkey window. Only replay a queued sync when user data actually changed.
- Avoid syncing on every short tab switch. Foreground sync should be
  application-configurable and gated by time away plus operation state.

Add regression coverage for the authorization feedback loop: opening and
closing an OAuth/passkey window during an active sync must not queue another
sync or reopen authorization indefinitely.

## Compatibility requirements

Do not change the current v1 behavior:

- EasyBC AAD and HKDF labels.
- Family Chores AAD and HKDF labels.
- Existing Drive filenames.
- Existing envelope fields and optional compression behavior.
- Existing WebAuthn credential IDs, PRF inputs, salts, and RP-ID checks.

Changing any of these can make existing snapshots undecryptable. Each
application defines and owns its compatibility profile containing the exact
filename, AAD, HKDF info, accepted envelope versions, compression behavior,
and app identity. The package owns the profile type/factory and protocol
validation, not named application presets.

Create deterministic, user-data-free compatibility fixtures from both current
implementations before moving code.

### v2 migration

Support a v2 envelope with an explicit `appId`:

```ts
{
  schemaVersion: 2,
  appId: "family-chores",
  algorithm: "AES-256-GCM+HKDF-SHA-256",
  // ...
}
```

Reject v2 envelopes whose `appId` does not match the configured application.
Authenticate security-relevant v2 header fields through a canonical AAD
representation. Retain v1 readers indefinitely.

Do **not** automatically rewrite an existing v1 snapshot as v2 during an
ordinary sync. Profiles need separate `readVersions` and `writeVersion`
settings so migrations are explicit and reversible.

EasyBC Android currently reads and writes v1 independently of npm. Therefore,
EasyBC web must continue writing v1 until the Android implementation can read
v2 and a staged rollout has been completed. A web-only v2 write would break
cross-device sync. Apply the same compatibility check to any non-JavaScript
consumer before changing its write version.

## Cross-app and shared-domain isolation

Test each isolation layer separately:

- OAuth authorized JavaScript origins are origin-level, not path-level.
  `/easy-bc/` and `/family-chores/` on `keyneom.github.io` share one browser
  origin and must be treated as mutually trusted.
- Google Drive `appDataFolder` access is scoped by the OAuth application, but
  exact app-specific filenames must still be preserved.
- WebAuthn passkeys are RP-ID scoped to the host, not a URL path. Always use an
  exact `allowCredentials` credential ID and distinct application display
  names.
- Cryptographic AAD/HKDF contexts and v2 `appId` checks must remain distinct
  even when applications share a domain or provider account.

EasyBC must never select, decrypt, overwrite, or delete Family Chores data, and
vice versa.

## Platform behavior

EasyBC web and Family Chores use:

- `/snapshot`
- `/keys/web-passkey`
- `/auth/google-web`
- `/stores/google-drive`

EasyBC Android remains a native compatibility consumer. Keep cross-platform
crypto fixtures between WebCrypto and Kotlin and coordinate any envelope
writer-version change with Android.

Keynote can reuse `/core`, `/crypto`, and `/stores/google-drive`, but should
provide its own synchronization model and desktop authorization/key adapters.
Keynote is a Tauri application, so Google OAuth must open in the system browser
using Authorization Code + PKCE with a supported loopback or deep-link redirect
flow. Do not run Google authorization inside the Tauri webview. Its SQLite
notes and attachments may require encrypted manifests and independently
addressed blobs rather than one large snapshot.

Design provider contracts so future adapters can be added without changing
core orchestration, for example:

- `/auth/google-web`
- `/auth/google-desktop`
- `/stores/google-drive`
- `/stores/webdav`
- `/stores/s3-compatible`
- `/keys/web-passkey`
- `/keys/desktop-keystore`

Do not implement speculative providers in v0.1.0; validate the interfaces with
the current providers and one desktop design first.

## Implementation sequence

1. Freeze deterministic v1 compatibility fixtures from EasyBC web, EasyBC
   Android, and Family Chores.
2. Scaffold one package with subpath exports and no root/browser side effects.
3. Extract provider-neutral crypto, envelope, compression, and error code.
4. Implement the consumer-defined profile contract. Keep EasyBC-v1 and
   Family-Chores-v1 definitions under compatibility tests, not runtime exports.
5. Extract WebAuthn, Google web authorization, and Drive adapters.
6. Implement `createSnapshotSync<T>()` with serialized operations, unlock/token
   coalescing, session locking, no-op suppression, and reentrancy protection.
7. Port EasyBC web first in v1-write mode. Verify current Android/web snapshots
   still decrypt and continue syncing in both directions.
8. Port Family Chores and run its entity-merge/deletion tests.
9. Add explicit cross-app, shared-origin, and provider-isolation tests.
10. Run package-manager and consumer build matrices, then publish `v0.1.0`.
11. Add v2 readers. Change an application's writer to v2 only after every
    active consumer for that application can read v2.
12. Integrate Keynote only after defining its desktop key provider,
    system-browser OAuth flow, and manifest/blob synchronization strategy.

## Required tests

- Existing EasyBC web, EasyBC Android, and Family Chores v1 fixtures decrypt
  unchanged.
- Encrypt/decrypt round trips, including compressed and uncompressed payloads.
- Tampered ciphertext or authenticated v2 header data fails authentication.
- Wrong passkey fails and clears cached key material.
- Wrong v2 `appId` is rejected before any write/delete.
- EasyBC cannot select or modify Family Chores data.
- App-specific filenames and cryptographic contexts remain distinct.
- Independent edits and deletions merge correctly.
- Stable fingerprints ignore volatile export timestamps but include all
  user-authored/configuration data.
- An unchanged merge performs no encryption or cloud write.
- Concurrent sync calls serialize; concurrent unlock/token requests coalesce.
- A local change during sync queues one follow-up sync.
- OAuth/passkey visibility changes during sync queue no follow-up sync.
- A valid in-memory OAuth token and derived key avoid repeated prompts.
- Token expiry, HTTP 401, explicit lock, and background timeout clear the
  appropriate session state.
- Importing the root or `/core` does not access `window`, `document`,
  `navigator`, or Google scripts.
- Browser provider modules have no side effects until explicitly initialized.
- npm and pnpm package installs succeed.
- Vite, Next.js, and Tauri frontend fixture builds succeed.
- Type declarations and both ESM and supported bundler resolution work through
  every documented subpath export.

## Existing source implementations

- EasyBC web:
  `/Users/micaelsanchez/repos/easy-bc/web/src/sync/`
- EasyBC web integration:
  `/Users/micaelsanchez/repos/easy-bc/web/src/App.tsx`
- EasyBC Android:
  `/Users/micaelsanchez/repos/easy-bc/android/app/src/main/java/com/easybc/planner/sync/`
- Family Chores:
  `/Users/micaelsanchez/repos/family-chores/sync/`
- Family Chores integration:
  `/Users/micaelsanchez/repos/family-chores/components/modals/SyncModal.tsx`

Use the current implementations and their fixtures as compatibility sources.
Avoid independent format refactors in either application while extraction is
underway. Land adapter-based migrations one consumer at a time, keeping each
step releasable and backward compatible.

## Sharing extension

Shared multi-user backups are a separate protocol and do not modify v1 private
snapshots. Its architecture, security limits, and per-file Drive flow are in
`docs/shared-backups.md`; phased implementation gates are in
`docs/sharing-execution-plan.md`.

Static-frontend operation without an application-owned trusted backend is a
normative objective. The required path uses Google Identity Services, Google
Drive, WebCrypto, and WebAuthn/passkeys from the client. Optional backend
automation must not become a protocol trust root or interoperability
requirement.

Use `docs/sharing-implementation-handoff.md` as the authoritative continuation
brief for the settled storage layout, permissions, exchange retention, security
checks, and remaining release blockers.

The first build adds `/sharing`, `/sharing/web-crypto`, and a normal-Drive
`GoogleDriveFileStore`. Do not route existing private snapshots through these
APIs or move them out of `appDataFolder`.
