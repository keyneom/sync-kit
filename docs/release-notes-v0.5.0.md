# sync-kit 0.5.0

Opt-in **participant keys** and **recovery codes**, on web and Android. A
participant can hold keys in addition to their passkey-protected identity — most
importantly one sealed under a generated recovery code — so a lost passkey is
recoverable, including for data other people own and share with them.

The full design, rules, and security analysis are in
`docs/participant-keys.md`.

## Nothing changes unless you opt in

- **Library.** Additional keys exist only when an app calls the new APIs. Every
  existing call path behaves as before; a dataset that never opts in is
  byte-for-byte unchanged.
- **Per dataset.** An owner or admin enables it with
  `setParticipantKeysPolicy`. It is off by default. Turning it off removes every
  additional key in the same revision.
- **Per user.** The app decides who sees the toggle — for example, an owner
  choosing per keyring whether it accepts recovery codes.

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
`getDatasetParticipantKeys`, and `participantKeyCoverage`.

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
`npm run parity:participant-keys:check` runs the reverse: Android writes a history
and the web package verifies it and opens the Android-sealed recovery key. Both
run in `npm run check`.

## Not included

- **Automatic hand-off of a viewer's signed operations to a writer.** Everything
  a writer needs to carry them is in place; moving them there is left to the app
  for now, because doing it through the control ledger would make pre-0.5.0
  readers reject the whole ledger.
- **Private v1 snapshots**, whose format is frozen. Keep private data in a
  single-participant shared dataset to gain recovery.
