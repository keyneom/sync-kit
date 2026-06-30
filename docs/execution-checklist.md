# Execution checklist

Use this as the phase gate for implementation. Do not mark a phase complete
until its tests and artifacts exist in this repository.

## Phase 0: freeze compatibility

- [ ] Record exact EasyBC v1 filename, envelope shape, AAD, HKDF info, PRF
      input, KDF salt handling, RP ID, compression threshold/encoding, and
      base64url behavior.
- [ ] Record the equivalent Family Chores constants and envelope behavior.
- [ ] Add deterministic, user-data-free EasyBC web fixtures.
- [ ] Prove the same EasyBC fixtures pass through the Android implementation.
- [ ] Add deterministic, user-data-free Family Chores fixtures.
- [ ] Add failure fixtures for tampering, wrong credentials/context, malformed
      envelopes, and decompression errors.
- [ ] Document the fixture-generation procedure and provenance.

Exit gate: both current applications consume the frozen fixtures unchanged.

## Phase 1: package and provider-neutral primitives

- [ ] Select and configure TypeScript build, declaration, lint, and test tools.
- [ ] Define explicit subpath exports for `/core`, `/crypto`, and `/snapshot`
      without browser dependencies.
- [ ] Implement base64url, HKDF-SHA-256, AES-256-GCM, canonical AAD, envelope
      parsing, optional gzip, and standardized errors.
- [ ] Implement explicit EasyBC-v1 and Family-Chores-v1 profiles.
- [ ] Test compressed/uncompressed round trips and all frozen fixtures.
- [ ] Verify importing root/core in Node does not touch browser globals.

Exit gate: provider-neutral code passes v1 compatibility tests without reaching
Google Drive, WebAuthn, or consumer schemas.

## Phase 2: browser adapters

- [ ] Implement `/keys/web-passkey` with exact `allowCredentials` behavior,
      raw-secret zeroing, unlock coalescing, and explicit cache clearing.
- [ ] Implement `/auth/google-web` with memory-only token reuse, expiry skew,
      request coalescing, HTTP 401 invalidation, and no import-time script load.
- [ ] Implement `/stores/google-drive` with exact filename lookup,
      `appDataFolder` scoping, safe create/update/delete, and provider errors.
- [ ] Add mocked provider tests, including concurrent and failure paths.

Exit gate: adapters are side-effect free until initialized and expose no
persistent key/token storage.

## Phase 3: snapshot orchestration

- [ ] Implement `createSnapshotSync<T>()` and explicit controller state.
- [ ] Serialize cloud operations.
- [ ] Queue at most one follow-up for a real local change during sync.
- [ ] Suppress OAuth/passkey visibility feedback loops.
- [ ] Suppress encryption and upload when stable merged fingerprints match.
- [ ] Implement explicit lock/reset/delete semantics.
- [ ] Add regression coverage for authorization feedback loops and races.

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

## Phase 5: packaging and v0.1.0

- [ ] Test npm and pnpm installs from a packed tarball.
- [ ] Build Vite, Next.js, and Tauri frontend fixtures through documented
      subpath exports.
- [ ] Verify ESM, declarations, tree-shaking boundaries, and supported module
      resolution.
- [ ] Resolve npm name, license, repository URL, ownership, and release
      provenance.
- [ ] Remove `"private": true` only after the preceding decision is explicit.
- [ ] Publish v0.1.0 and verify consumers against the published artifact.

Exit gate: installed artifacts, not source-link shortcuts, pass the matrix.

## Deferred: v2 and desktop adapters

- [ ] Add v2 readers with canonical authenticated headers and explicit `appId`.
- [ ] Keep v1 readers indefinitely.
- [ ] Do not auto-rewrite v1 during ordinary sync.
- [ ] Change writer versions only after every active consumer can read v2.
- [ ] Design Keynote system-browser OAuth, desktop keys, and manifest/blob sync
      before implementing desktop provider adapters.
