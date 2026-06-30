# sync-kit

`sync-kit` is the planned standalone TypeScript package for reusable encrypted
application-data synchronization. It will provide provider-neutral crypto and
sync orchestration plus opt-in browser adapters for WebAuthn PRF, Google
Identity Services, and Google Drive `appDataFolder`.

Status: **planning scaffold only**. No runtime implementation has been extracted
yet. The package is intentionally marked private until its public npm name,
license, and release ownership are decided.

## Why this repository exists

EasyBC and Family Chores independently implement the same core encrypted-sync
model. This repository will extract that proven behavior into one package
without changing either application's persisted v1 format. Keynote is a future
desktop consumer and is the reason the core must not depend on browser globals.

The name `sync-kit` is deliberately capability-oriented. `private-sync` would
overstate what the library can guarantee: applications and provider
configuration still determine metadata exposure, account isolation, conflict
behavior, and lifecycle policy.

## Planned package surface

```text
sync-kit
├── /core
├── /crypto
├── /snapshot
├── /keys/web-passkey
├── /auth/google-web
└── /stores/google-drive
```

This remains one package with subpath exports. Root and provider-neutral imports
must have no browser globals or import-time side effects.

## Non-negotiable compatibility rules

- Preserve EasyBC and Family Chores v1 filenames, envelope fields, AAD, HKDF
  labels, passkey inputs, salts, RP-ID validation, and compression behavior.
- Freeze deterministic, user-data-free fixtures before extracting code.
- Keep EasyBC writing v1 until both web and Android can read any replacement
  version.
- Keep schema validation, merge policy, tombstones, local persistence, UI, and
  lifecycle policy in each application.
- Never store raw PRF output, derived keys, or OAuth tokens in persistent
  browser storage.
- Never let EasyBC select, decrypt, overwrite, or delete Family Chores data,
  or vice versa.

## Start here in the next session

1. Read [the implementation plan](docs/implementation-plan.md).
2. Verify [the source inventory](docs/source-inventory.md) against the live
   consumer repositories; Family Chores sync code is currently uncommitted.
3. Complete Phase 0 in [the execution checklist](docs/execution-checklist.md):
   freeze fixtures and record exact format constants before creating runtime
   modules.
4. Scaffold TypeScript build/test tooling and the documented subpath exports.
5. Extract provider-neutral primitives first; do not begin by porting consumer
   UI or merge logic.

## Documentation

- [Implementation plan](docs/implementation-plan.md): architecture,
  responsibilities, compatibility contract, required tests, and full sequence.
- [Execution checklist](docs/execution-checklist.md): phase gates and concrete
  deliverables.
- [Source inventory](docs/source-inventory.md): current source repositories,
  revisions, and extraction inputs.

## Publishing

Do not remove `"private": true` from `package.json` until all of these are
explicitly resolved:

- npm name availability and whether the package will be public;
- repository license;
- release ownership and provenance;
- the consumer compatibility matrix passing from installed tarballs.
