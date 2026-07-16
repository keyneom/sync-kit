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

Validated on 2026-07-01 for the unpublished sharing extension:

- deterministic fixtures, Java sharing-fixture verification, lint, strict
  typecheck, 50 tests, declarations, and
  build;
- packed-tarball npm and pnpm installs plus every sharing subpath import;
- mocked owner/invite/response/accept/recipient-write flow;
- passkey-key-encrypted sharing identity round trip;
- conditional Drive request headers and stale-write rejection.

Live Google Picker, Drive ETag/permission behavior, Google/passkey account
attestation, consumer integration, and native fixture consumption remain open.

Validated on 2026-07-03 for the unpublished sharing review fixes:

- locale-independent UTF-16 code-unit canonical and protocol ordering;
- owner-pin preservation and enforcement during invitation exchange;
- queued local changes that arrive after a queued sync starts;
- retryable Drive folder/storage initialization after transient failures;
- a 256-entry signed revision-ancestry window with explicit fork policy beyond
  that window;
- passkey cache separation by PRF input, cross-package error recognition,
  conditional-write response reuse, and installed-artifact default exports;
- lint, strict typecheck, 56 tests, build, unchanged deterministic fixtures,
  Java sharing-fixture verification, and packed npm/pnpm consumer imports.

The live Google and external-consumer release gates remain open.

Validated on 2026-07-09 for the control-dataset and hard-cutover work:

- encrypted, per-cohort control state with individually signed member,
  migration, acknowledgement, and close events;
- pinned control-owner enforcement, expected-Picker-file acknowledgement
  validation, and an owner-held close gate;
- a mixed-codec invitation/accept path that grants a control dataset beside
  ordinary application datasets in one response flow;
- focused control-dataset tests, full lint/typecheck/test/build/package gate,
  frozen fixtures, Java fixture verification, and JS/Kotlin parity checks.

Live Google multi-select Picker and two-account post-accept control-file
enrollment remain open release-validation gates.

Validated on 2026-07-11 for Android control-dataset parity:

- Kotlin control state/event models, exact wire parsing, canonical signing,
  pinned-owner verification, deterministic event-union merge, and UTF-16
  ordering;
- owner-only membership/migration/close actions, participant self-acknowledgement,
  exact Picker-file acknowledgement, and force-close semantics;
- per-dataset codec selection across load/sync, invite acceptance, role changes,
  and revocation, plus verified dataset trust and participant provenance APIs;
- a fixed TypeScript/Kotlin control merge vector and an Android mixed-codec
  invitation/response integration test covering one app dataset plus one
  control dataset.

Validated on 2026-07-12 for the `0.2.0-rc.15` participant-grant correction:

- TypeScript and Kotlin direct known-key grants now share the established
  participant-upsert behavior used by verified invitation acceptance;
- mixed-codec control datasets select their per-dataset codec on both
  platforms, including the hard-cutover path used by EasyBC web and Android;
- signed envelope creation and conditional publication complete before Drive
  ACL changes, so failed writes do not leave untracked writer permissions;
- viewer grants reuse inherited reader access instead of creating redundant
  direct permissions;
- mocked web and Android Drive transports verify recovery-safe trash requests;
- the authoritative repository gate passed unchanged fixtures, the native
  Java verifier, the complete Android unit suite, JS/Kotlin parity checks,
  lint, strict typecheck, 135 TypeScript tests, build, and packed npm/pnpm
  consumer imports.

Validated on 2026-07-12 for the `0.2.0-rc.16` control-event signing correction:

- TypeScript and Kotlin normalize set-like v1 control-event arrays before
  signing and persist the same representation covered by the signature;
- a shared fixture deliberately reverses source dataset and target file IDs,
  and both runtimes verify the resulting signed migration announcement;
- no compatibility verifier for pre-release malformed events is retained.

Validated on 2026-07-16 for `0.2.0-rc.17` accessible `drive.file` dataset
discovery:

- TypeScript and Kotlin enumerate every managed sharing dataset already granted
  to the token even when its parent app-root is not listable;
- both runtimes exhaust Drive pages, skip malformed/unrelated metadata,
  deduplicate by file ID, and sort by app-folder ID, dataset ID, then file ID
  using matching UTF-16 ordering from one shared fixture;
- `listDatasets()` and metadata-head listing resolve existing storage without
  creating an app-root or `exchanges` folder;
- `npm run check` passed the unchanged compatibility fixtures, complete Android
  unit suite, private/sharing parity gates, lint, strict typecheck, 140
  TypeScript tests, build, and packed npm/pnpm consumer imports;
- the release remains gated on normal consumer validation rather than a
  package-owned interactive emulator harness.

## Android library (private snapshots)

- [x] Extract profile-driven v1 envelope crypto, snapshot controller, Drive
      `appDataFolder` store, and Credential Manager passkey provider into
      `android/synckit` (`com.keyneom:sync-kit-android`).
- [x] Prove EasyBC fixtures in Android library unit tests (including 32-byte
      PRF input enforcement).
- [x] Add `npm run parity:check` (JS + Kotlin reports, identical-section diff,
      mutual decrypt of compressed peer envelopes).
- [x] Migrate EasyBC Android to depend on the library via `includeBuild`.
- [x] Publish `sync-kit-android` to GitHub Packages on version tags
      (`.github/workflows/publish-android.yml`).
- [ ] Cut a tagged Android release (`v0.2.0-rc.1`) and verify consumer install
      from GitHub Packages.
- [x] Port shared-backup (`/sharing`) APIs to Android (primary sharing target).

## Deferred: v2 and desktop adapters

- [ ] Add v2 readers with canonical authenticated headers and explicit `appId`.
- [ ] Keep v1 readers indefinitely.
- [ ] Do not auto-rewrite v1 during ordinary sync.
- [ ] Change writer versions only after every active consumer can read v2.
- [ ] Design Keynote system-browser OAuth, desktop keys, and manifest/blob sync
      before implementing desktop provider adapters.

## Deferred: recovery, audits, and operational hardening

- [ ] Expose Drive file-revision recovery helpers so a conflict or lost race can
      list prior revisions, fetch a chosen revision's envelope, and feed it
      through the existing decrypt/merge/fork path (prevention via `If-Match`
      remains primary; revision history is the ambulance).
- [ ] Keep accepted key-response exchange files for audit while early sharing
      deployments are being validated. Only delete immediately when a verified
      account binding carried a raw Google ID token (current behavior). After a
      long clean run, switch non-binding responses to post-accept cleanup (or a
      short retention window) so `exchanges/` does not accumulate forever.
- [ ] Consider optional payload/schema version signals on envelopes (min reader
      version, writer version) and controller hooks that surface
      "remote requires a newer app" without owning update UI or install flows.

## Extension: shared encrypted backups

- [x] State static-frontend operation without an application-owned trusted
      backend as a package objective and protocol requirement.
- [x] Document the sharing protocol, per-file permission model, key exchange,
      role semantics, and security limits.
- [x] Add browser-independent sharing types and strict parsers.
- [x] Add WebCrypto identities, signed invitations/key responses,
      per-recipient content-key grants, signed revisions, and role enforcement.
- [x] Add a normal-Drive `drive.file` store with explicit per-file sharing.
- [x] Add an overrideable app-owned top-level folder default for new file-backed
      snapshots while retaining explicit `appDataFolder` compatibility.
- [x] Make shared metadata visibility the simple default and retain direct-file
      or limited-folder isolation as an explicit developer option.
- [x] Preserve all existing v1 private-snapshot fixtures and behavior.
- [x] Freeze a synthetic sharing-v1 WebCrypto fixture.
- [x] Add multi-dataset invitations and durable signed acceptance provenance.
- [x] Add a headless sharing controller and managed Google Drive sharing
      transport.
- [x] Add passkey-encrypted sharing identity records and optional IndexedDB
      ciphertext persistence.
- [x] Add mocked conditional-write and stale-writer conflict coverage.
- [x] Validate the sharing-v1 fixture with Java before claiming Java
      compatibility.
- [x] Add Picker/Open-with, Google/passkey account attestation, signed ancestry,
      fork policy, and dual-proof key rotation.
- [x] Execute sharing exchange/decryption from packed npm and pnpm artifacts.
- [x] Add metadata-only `listDatasetHeads`, `SharingChangeDetector`, and
      `SharingSyncCheckpoint` on npm `/sharing`.
- [x] Add opt-in `IndexedDbAuthorizationCache`, `bindSharingPoll`, and SW
      integration guidance.
- [x] Add Kotlin sharing fixture verification and Android sharing port (S7).
- [x] Add first-class Kotlin sharing account-binding creation and verification,
      strict registration COSE/JWK extraction, exact Android APK origins,
      bounded JWKS caching/rotation, controller-hook coverage, and
      identity-preserving replacement-credential migration primitives.
- [x] Match the canonical account-binding challenge in TypeScript and Kotlin
      and test Google/WebAuthn signatures without live endpoints.
- [ ] Validate Credential Manager registration/assertion on a real API 28+
      Android device with Digital Asset Links and release/debug origin policy.
- [ ] Wire EasyBC Android Google ID-token acquisition with the server/web OAuth
      client ID, migrate existing protected identities without public keys, and
      enable required account binding only after a real two-account web↔Android
      exchange succeeds.
- [x] Add an encrypted, signed control dataset for Picker enrollment,
      participant provenance, and hard-cutover migration acknowledgements.
- [x] Let one invitation accept a protocol-owned control codec beside
      application-owned dataset codecs, with focused mixed-codec tests.
- [ ] Validate OAuth, Picker, conditional writes, permissions, and account
      attestation against live Google services (`npm run live:drive`).
- [ ] Integrate the complete flow into an external consumer from a packed
      artifact.

Detailed gates: `docs/sharing-execution-plan.md`.
Continuation handoff: `docs/sharing-implementation-handoff.md`.
