# Execution checklist

Use this as the phase gate for implementation. Do not mark a phase complete
until its tests and artifacts exist in this repository.

## Phase 0: freeze compatibility

- [x] Record exact EasyBC v1 filename, envelope shape, AAD, HKDF info, PRF
      input, KDF salt handling, RP ID, compression threshold/encoding, and
      base64url behavior.
- [x] Record the equivalent Family Chores constants and envelope behavior.
- [x] Add deterministic, user-data-free EasyBC web fixtures.
- [x] Prove the same EasyBC fixtures pass through the Android implementation.
- [x] Add deterministic, user-data-free Family Chores fixtures.
- [x] Add failure fixtures for tampering, wrong credentials/context, malformed
      envelopes, and decompression errors.
- [x] Document the fixture-generation procedure and provenance.

Exit gate: both current applications consume the frozen fixtures unchanged.

Status: not fully closed. EasyBC web and Android already consume their shared
fixture. The Family Chores fixture was generated from and checked once against
its live, uncommitted crypto module, but Family Chores does not contain a
maintained test that imports this repository's fixture. Close this gate during
the Family Chores consumer migration.

## Phase 1: package and provider-neutral primitives

- [x] Select and configure TypeScript build, declaration, lint, and test tools.
- [x] Define explicit subpath exports for `/core`, `/crypto`, and `/snapshot`
      without browser dependencies.
- [x] Implement base64url, HKDF-SHA-256, AES-256-GCM, canonical AAD, envelope
      parsing, optional gzip, and standardized errors.
- [x] Implement the consumer-defined v1 profile contract and keep EasyBC /
      Family Chores definitions in compatibility tests only.
- [x] Test compressed/uncompressed round trips and all frozen fixtures.
- [x] Verify importing root/core in Node does not touch browser globals.

Exit gate: provider-neutral code passes v1 compatibility tests without reaching
Google Drive, WebAuthn, or consumer schemas.

## Phase 2: browser adapters

- [x] Implement `/keys/web-passkey` with exact `allowCredentials` behavior,
      raw-secret zeroing, unlock coalescing, and explicit cache clearing.
- [x] Implement `/auth/google-web` with memory-only token reuse, expiry skew,
      request coalescing, HTTP 401 invalidation, and no import-time script load.
- [x] Implement `/stores/google-drive` with exact filename lookup,
      `appDataFolder` scoping, safe create/update/delete, and provider errors.
- [x] Add mocked provider tests, including concurrent and failure paths.

Exit gate: adapters are side-effect free until initialized and expose no
persistent key/token storage.

## Phase 3: snapshot orchestration

- [x] Implement `createSnapshotSync<T>()` and explicit controller state.
- [x] Serialize cloud operations.
- [x] Queue at most one follow-up for a real local change during sync.
- [x] Suppress OAuth/passkey visibility feedback loops.
- [x] Suppress encryption and upload when stable merged fingerprints match.
- [x] Implement explicit lock/reset/delete semantics.
- [x] Add regression coverage for authorization feedback loops and races.

Exit gate: the required concurrency, no-op, lifecycle, and session tests in the
implementation plan pass.

## Phase 4: consumer migrations

- [ ] Pack the library and install the tarball into EasyBC web.
- [ ] Port EasyBC web in v1-write mode without changing Android behavior.
- [ ] Verify web-to-Android and Android-to-web fixture/sync compatibility.
- [ ] Pack and install into Family Chores.
- [ ] Re-run Family Chores merge and deletion/tombstone tests.
- [ ] Add cross-app isolation tests proving neither app can read/write/delete
      the other's snapshot.

Exit gate: both web consumers use the package and all native/consumer
compatibility checks pass.

## Phase 5: packaging and v0.1.x

- [x] Test npm and pnpm installs from a packed tarball.
- [ ] Build Vite, Next.js, and Tauri frontend fixtures through documented
      subpath exports.
- [ ] Verify ESM, declarations, tree-shaking boundaries, and supported module
      resolution.
- [ ] Resolve npm name, license, repository URL, ownership, and release
      provenance.
- [x] Remove `"private": true` only after the public-package decision is
      explicit.
- [x] Publish v0.1.0.
- [x] Publish v0.1.1 with consumer-owned profiles and no consumer fixtures in
      the package artifact.
- [ ] Verify consumers against the published artifact.

Exit gate: installed artifacts, not source-link shortcuts, pass the matrix.

## Validation record

Validated on 2026-06-30:

- this repository: lint, strict typecheck, 22 unit/integration tests,
  declarations, and deterministic-fixture check;
- packed-tarball npm and pnpm installs plus every documented subpath import;
- npm publication of public `@keyneom/sync-kit@0.1.1` with the `latest` tag;
- unchanged external baseline checks: EasyBC web's 15 existing sync
  crypto/session/token/key tests, EasyBC Android's existing `SyncCryptoTest`
  with OpenJDK 17, and Family Chores's 5 existing sync crypto/merge tests;
- one temporary extraction-time check imported Family Chores's live
  `sync/crypto.ts` and decrypted the frozen deterministic fixture. That check
  was deleted after running and is not a maintained consumer test.

No package tarball was installed into EasyBC, Family Chores, or Keynote, and no
consumer repository was changed. Phase 4 remains entirely unchecked.

## Deferred: v2 and desktop adapters

- [ ] Add v2 readers with canonical authenticated headers and explicit `appId`.
- [ ] Keep v1 readers indefinitely.
- [ ] Do not auto-rewrite v1 during ordinary sync.
- [ ] Change writer versions only after every active consumer can read v2.
- [ ] Design Keynote system-browser OAuth, desktop keys, and manifest/blob sync
      before implementing desktop provider adapters.
