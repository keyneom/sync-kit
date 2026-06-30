# Source inventory

Captured on 2026-06-29. Re-check every path and revision before extraction.
These repositories remain the compatibility sources; this document is not a
substitute for fixture-backed verification.

Re-checked on 2026-06-29 before implementation:

- EasyBC remained clean at the captured revision.
- Family Chores remained at its captured base revision with the sync
  implementation and tests still uncommitted.
- Keynote remained at the captured revision, with its branch 12 commits ahead
  of origin and no local worktree changes.
- EasyBC web sync tests, EasyBC Android `SyncCryptoTest`, and Family Chores sync
  crypto/merge tests passed as unchanged baseline checks after extraction.
- No package tarball was installed and no source file was changed in any
  consumer repository.

## EasyBC

- Repository: `/Users/micaelsanchez/repos/easy-bc`
- Captured revision: `e6d3250af204f0e1a8b8fe25fd276b24a70f42b3`
- Captured state: clean worktree
- Web implementation: `web/src/sync/`
- Web integration: `web/src/App.tsx`
- Android implementation:
  `android/app/src/main/java/com/easybc/planner/sync/`
- Android tests:
  `android/app/src/test/java/com/easybc/planner/sync/`

Important web inputs:

- `crypto.ts` and `crypto.test.ts`
- `types.ts` and `types.test.ts`
- `googleDrive.ts` and `googleDrive.test.ts`
- `passkey.ts`
- `keySession.ts` and `keySession.test.ts`
- `sessionSync.ts`, unit tests, and integration tests
- `autoSyncState.ts` and tests

Important Android inputs:

- `SyncModels.kt`
- `SyncCrypto.kt`
- `CloudSyncCoordinator.kt`
- `CloudSyncKeySession.kt`
- `CloudAutoSyncSession.kt`
- `GoogleAuthorization.kt`
- `GoogleDriveSyncClient.kt`
- `PasskeyPrfClient.kt`

EasyBC web and Android are active cross-platform consumers of the same v1
snapshot. Any fixture set must prove both implementations agree.

## Family Chores

- Repository: `/Users/micaelsanchez/repos/family-chores`
- Captured base revision: `60ef3428b8613b756de42668d04b5fe88f0af157`
- Captured state: dirty worktree; the sync implementation and tests are
  uncommitted and therefore are **not represented by the revision above**
- Sync implementation: `sync/`
- UI integration: `components/modals/SyncModal.tsx`
- local-state integration: `components/ChoresAppContext.tsx`
- tests: `tests/sync/`
- browser smoke test: `e2e/smoke/encrypted-sync.spec.ts`

Important extraction inputs:

- `sync/crypto.ts`
- `sync/googleDrive.ts`
- `sync/passkey.ts`
- `sync/storage.ts`
- `sync/types.ts`

Read the live working tree. Do not use `git show` at the captured revision as
the Family Chores compatibility source.

## Keynote

- Repository: `/Users/micaelsanchez/repos/keynote`
- Captured revision: `a22978fcfe0efdccf64352f11d49e61510163fe0`
- Captured state: clean worktree
- Role: future contract-design consumer only

Keynote is a Tauri/SQLite application. It should validate that provider
interfaces can support system-browser Authorization Code + PKCE and a
manifest/blob model, but speculative desktop providers are out of scope for
v0.1.0.

## Originating handoff

The standalone implementation plan originated at:

`/Users/micaelsanchez/repos/easy-bc/docs/sync-kit-extraction-handoff.md`

The copy in this repository is authoritative for extraction work. Consumer
repositories remain authoritative for actual persisted compatibility behavior.
