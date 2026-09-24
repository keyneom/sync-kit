# sync-kit 0.5.0

Opt-in **participant keys** and **recovery codes**, on web and Android. A
participant can hold keys in addition to their passkey-protected identity — most
importantly one sealed under a generated recovery code — so a lost passkey is
recoverable, including for data other people own and share with them. Private
snapshots gain the same through an opt-in **snapshot v2**.

The full design, rules, and security analysis are in
`docs/participant-keys.md` and `docs/snapshot-recovery.md`.

## Nothing changes unless you opt in

- **Library.** Additional keys exist only when an app calls the new APIs. Every
  existing call path behaves as before; a dataset that never opts in is
  byte-for-byte unchanged.
- **Per dataset.** An owner or admin enables it with
  `setParticipantKeysPolicy`. It is off by default. Turning it off removes every
  additional key in the same revision.
- **Per user.** The app decides who sees the toggle — for example, an owner
  choosing per keyring whether it accepts recovery codes.

Behavior and stored formats are unchanged unless you opt in. The exported
**types** are not — see below.

## Type changes that can break a build

0.5.0 widens some exported types. Runtime behavior is unaffected — an app that
never opts in never sees the new values — but code that assumes the old, closed
set fails to compile. Note that `vite build` does not typecheck, so a green build
can hide this until a later `tsc` step (for example a deploy that runs
`npm run typecheck`).

Web:

- `SnapshotOperation` gains `"recover"` and `SyncOutcome` gains `"recovered"`. An
  exhaustive `switch` over either reports "lacks ending return statement" (or
  fails an exhaustiveness check). Add the case, or type the parameter with your
  own narrower union so future additions cannot reach you.
- `SyncEnvelopeV1.schemaVersion` and the shared-backup envelope's
  `schemaVersion` are `1 | 2` instead of `1`.
- `V1CompatibilityProfile` has `readVersions: readonly (1 | 2)[]` and a new
  required `writeVersion`. Profiles built with `defineV1CompatibilityProfile`
  are unaffected; an object literal typed as the profile needs `writeVersion: 1`.
- `SnapshotSyncController` gains `setRecoveryCode`, `recover`, and
  `migrateVersion`, and `SharedBackupController` gains the participant-key
  methods. A hand-written implementation or test double of either interface
  needs them, or should be typed with `Pick` or `Partial`.

Android:

- `SnapshotOperation.RECOVER` and `SyncOutcome.RECOVERED` are new enum entries. A
  `when` expression over either without an `else` no longer compiles.

## Compatibility

A dataset whose history has ever enabled participant keys is written as
`schemaVersion: 2` and stays there. **Readers before 0.5.0 reject it** as
incompatible rather than silently dropping the extra keys' access on their next
write, which is what an unaware reader would otherwise do. Enable the policy on a
dataset only once every participant runs 0.5.0 or later.

## What is new

`/sharing/participant-keys` (Android: `com.keyneom.synckit.sharing.ParticipantKeys`):

- **Recovery codes** — 128 random bits as 28 characters with 2 check characters
  that catch typos. Codes are only ever generated, never chosen.
- **Recovery keys** — a sharing identity whose private keys are sealed under the
  code and stored inside every data file that grants it, so the code and **any
  one file** recover it, including an offline copy.
- **Signed operations** — add a key, remove a key, and replace a lost primary key
  with a rotation authorized by an additional key. Each is signed by the
  participant it concerns, so any writer can carry it, including for a viewer.

`SharedBackupController` gains `setParticipantKeysPolicy`, `addParticipantKeys`,
`removeParticipantKeys`, `rotateWithAdditionalKey`, `openRecoveryKey`,
`getDatasetParticipantKeys`, `participantKeyCoverage`, and
`replicateParticipantKeys`. Android also gains `rotateLocalKey`, which the web
controller already had.

### A viewer's keys reach the data it views

A viewer cannot write the data it views, but it is a writer in the profile's
control dataset. It applies its own additions, removals, and recovery rotations
there, and any writer's `replicateParticipantKeys` replays them — in order,
idempotently — into each dataset that writer can write, skipping datasets whose
owner has not enabled participant keys. No control-ledger format changes, so
readers of the ledger are unaffected.

### Private snapshot recovery (snapshot v2)

A private snapshot can carry a recovery code: `setRecoveryCode`, then `recover`
on a new device when the passkey is lost. This is the v2 envelope planned from
the start — explicit `appId`, every header field authenticated — and it is
opt-in per profile:

- v1 is byte-for-byte unchanged and readable indefinitely.
- A profile reads v2 only with `readVersions: [1, 2]`, and writes new snapshots
  as v2 only with `writeVersion: 2`. Ship reading to every device first.
- Ordinary sync never changes a snapshot's version. Only `setRecoveryCode` and
  the reversible `migrateVersion` do; moving back to v1 drops the code.
- A device that does not read v2 rejects a v2 snapshot as incompatible.

Recovery works on a fresh device before any dataset is registered, and an owner's
recovery does not change the dataset's trust root.

## Rules every reader enforces

Nobody can attach a key to someone else — additions need the participant's
signature even when an owner writes the entry. Only owners and admins change the
policy. Removing a participant removes all of their keys. An additional key never
carries its participant's admin authority, can never author a data revision, and
may only change its own participant's keys. A recovery rotation must verify even
when an admin carries it, so the history cannot record a recovery that never
happened. A removed key cannot be re-added from its old authorization.

## Verified across platforms

`fixtures/sharing-v1/participant-keys.json` is a web-written history that Android
verifies and decrypts, opening the recovery key from its code.
`fixtures/v2/snapshot-recovery.json` holds web-written v2 snapshots that Android
opens with the passkey and with the recovery code. `npm run parity:recovery:check`
runs both reverse checks: Android writes a participant-key history and a v2
snapshot, and the web package verifies and opens them. All of this runs in
`npm run check`, and the v1 parity check still passes unchanged.
