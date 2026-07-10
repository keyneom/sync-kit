# Shared control datasets and topology migration

A sharing profile may include a **control dataset**: an encrypted shared file
whose sole purpose is coordination. It is separate from application data so a
participant can report setup and migration status even when that participant is
only a viewer of the data being changed.

The control dataset is generic `sync-kit` protocol state. The application still
owns its data schema, the choice of split/merge, per-dataset codecs, and any UI.

## Why a separate control dataset exists

Google's `drive.file` scope is per-file. A direct Drive ACL makes a newly
created file available in Google Picker, but it does not make the app able to
read it until that account selects the file. A folder selection does not grant
recursive file access.

Consequently, a migration needs two channels:

1. **Target data files** — the user explicitly selects and the app decrypts
   each target file they are entitled to use.
2. **Already-enrolled control file** — the user signs an acknowledgement that
   reports the successfully opened target IDs.

The control file solves the communication problem after enrollment. It does
not bypass Picker consent for newly created target files.

## Initial sharing flow

Create one control dataset per coordination cohort. Its participants normally
have `writer` access even if they are `viewer`s of some data datasets. The
control payload contains only protocol metadata: public keys, accepted
account/Drive provenance, optional email metadata, migration records, and
acknowledgements. Do not put application data in it.

For a new recipient:

1. Owner creates the control dataset with only the owner as an encrypted
   participant.
2. Owner includes it as a `writer` `requestedGrant` in the *same* invitation
   as every initial data dataset.
3. Recipient uses a multi-select Picker flow and selects every file listed in
   the signed invitation, including the control file. The recipient may not be
   able to decrypt any of them until the owner accepts the response; selection
   is still what grants future `drive.file` access.
4. Recipient returns the signed public-key response. Owner accepts it for all
   datasets, then calls `control.synchronizeMembers(...)` to mirror the
   accepted public key plus user-facing email/Google provenance into the
   signed control directory.
5. Recipient opens the control dataset. It is now the durable channel for
   setup, migration, and status events.

One invitation and one response link are sufficient. Existing profiles need a
one-time control-file enrollment before the first destructive migration. Do not
delete old data while any required participant lacks that enrollment.

## Mixed application and control codecs

The control file has a package-owned payload schema, whereas each data file
uses the application's own codec. Construct a control controller using
`createSharingControlCodec()` and configure the application-data controller's
`codecForDataset` callback for the control dataset. That lets the existing
multi-dataset invitation/accept operation re-encrypt every granted file with
the correct codec.

```ts
const controlCodec = createSharingControlCodec();
const appController = createSharedBackupController({
  appId,
  codec: appDatasetCodec,
  codecForDataset: (datasetId) =>
    datasetId === controlDatasetId ? controlCodec : undefined,
  identity,
  transport,
  registry,
});
const controlController = createSharedBackupController({
  appId,
  codec: controlCodec,
  identity,
  transport,
  registry,
});
const control = createSharingControlDataset({
  controller: controlController,
  datasetId: controlDatasetId,
  profileId,
  identity,
});
```

The application chooses and persists the stable `controlDatasetId`; do not
derive correctness from its Drive filename.

## Picker UX contract

Present a single action such as **Grant access to this profile's files**. Open
Google Picker with multi-select enabled, show the signed expected file list in
the app, and compare the returned file IDs to that list.

- Do not treat folder access as success.
- Do not acknowledge until every required file has both been selected and
  decrypted/verified by the application.
- If one is missing, show its user-facing dataset label and reopen the Picker.
- Ignore every selected file that is not in the signed expected set. Before
  parsing any expected file, validate its app ID, dataset ID, pinned owner,
  envelope signature, and applicable role. Never execute content from Drive.

Google Picker supports multi-select but does not expose a documented API for an
application to select every file on the user's behalf. The application may
provide a button that opens the appropriately scoped multi-select flow, not a
button that silently grants all file access.

## Hard-cutover migration flow

The current control API coordinates migration state; it deliberately does not
know how to transform application payloads. A consumer performs the data work
and records the protocol state around it.

1. Ship a prior application version that recognizes the migration freeze and
   stops old-topology edits. Old clients that cannot recognize this marker are
   a residual compatibility risk, not a reason to dual-write private data.
2. An authorized application instance creates the target datasets, applies its
   pure split/merge transform, gives every target a fresh content key, and
   shares each target with its intended recipients.
3. Owner announces a `hard-cutover` migration in the already-enrolled control
   dataset. The record lists source dataset IDs, target file IDs/revisions, and
   the precise target file IDs each participant must open.
4. Each participant uses Picker, opens and verifies its required targets, then
   writes a signed acknowledgement into the control file.
5. The owner reads `migrationStatus()`. It may close the migration only when
   every required acknowledgement is present, or use an explicit, recorded
   force-close policy. The application then retains/trashes/deletes old data
   according to its own recovery policy.

Do not dual-write after a split introduces a narrower ACL. A recipient who
could decrypt a former consolidated file may retain its historical plaintext;
the migration protects future data in the new files, not past disclosure.

## Integrity and availability

Control state is an encrypted sharing envelope plus a merge-safe union of
individually signed events. The initial self-signed owner record must match the
pinned owner of the control dataset. Only that owner may add directory entries,
announce a migration, or close it; every required participant may sign only
their own acknowledgement.

Google/account provenance is useful audit evidence. Use the existing
Google-ID-token and passkey account binding to establish the durable Google
`sub`; retain email as the contact/Drive-ACL label. A Drive revision author is
additional corroboration, not a replacement for the cryptographic identity
binding.

As with all shared writable files, a legitimate writer can attempt availability
attacks such as write conflicts or flooding. Event signatures prevent forgery;
they do not make Drive deletion or denial of service impossible. Consumers
should surface a blocked migration rather than infer success from silence.

## Future: commit/reveal rounds and verifiable randomness

The same encrypted storage, participant keys, and signed event-log primitives
can later support an application-neutral commit/reveal helper. It is not part
of the control-dataset wire format yet.

### Simultaneous private choices

For a round with a hidden action, each participant signs a commitment over a
domain-separated canonical value:

```text
H(protocolVersion || appId || profileId || sessionId || roundId ||
  participantKeyId || "action" || action || randomNonce)
```

The shared round log contains only the commitment until every required
participant has committed. Each participant then reveals `action +
randomNonce`; peers recompute the hash and verify the event signature. A
participant cannot change an action after seeing another reveal.

### Multi-party randomness

A closely related round produces **verifiable multi-party randomness** without
a service-side random-number generator:

1. A designated host generates a 256-bit secret seed with the platform CSPRNG
   and signs `H(... || "host-seed" || seed)`. The seed stays local at this
   point.
2. Every required participant independently generates a 256-bit random input
   and signs `H(... || "participant-seed" || participantKeyId || input)`.
   Inputs also stay local while commitments are collected.
3. Once the required commitments are present, the host and participants reveal
   their original values. Each reveal must match its signed commitment.
4. Everyone derives exactly the same output from the host seed and the
   participants' inputs sorted by UTF-16 key ID:

   ```text
   digest = SHA-256(protocolVersion || appId || profileId || sessionId ||
                     roundId || "randomness" || hostSeed ||
                     (participantKeyId || participantInput)*)
   ```

   For a bounded integer, use rejection sampling rather than `digest % n`.
   For example, consume 32-bit words from `digest`, then from
   `SHA-256(digest || counter)`, rejecting each word `x` when
   `x >= floor(2^32 / n) * n`; the first accepted value is `x % n`.
   A result from 1 through 10 is therefore `1 + (x % 10)` with no modulo bias.

The commitments make the result reproducible and make post-commit seed changes
detectable. If at least one participant keeps an honestly unpredictable input
secret until commitments are fixed, no other participant can predict or choose
the final output in advance.

This is not proof that every contributor used a CSPRNG; it is a verifiable
result whose unpredictability relies on at least one honest, private input.

### Required event/state model

A future helper should use immutable, individually signed events such as:

```text
round-opened            required players, domain, outcome rule
host-seed-committed     host commitment
input-committed         one per participant
action-committed        optional one per participant
seed-revealed           host or participant reveal
action-revealed         participant reveal
round-finalized         derived digest, result, verified inputs
round-abandoned         missing reveal or explicit cancellation
```

The application owns its round rule and presentation. `sync-kit` can own
canonical serialization, commitment/reveal verification, domain separation,
unbiased bounded-number derivation, and typed round status.

### The unavoidable withholding problem

A commitment prevents a party from changing a value; it cannot force that
party to reveal. A host can still withhold its seed after learning enough to
dislike the outcome, and a participant can similarly block a reveal. Drive
timestamps and app clocks are not a neutral, enforceable timeout authority.

Therefore the default protocol must produce **no result** until every required
reveal arrives. It may surface an abandoned round and let the application apply
a clearly disclosed social rule (forfeit, cancel, or restart), but it must not
silently substitute a value or claim unbiased finality. A trusted time/random
beacon, escrow service, or game-specific penalty mechanism is needed when that
availability attack is unacceptable.

### Useful backend-free tools and games

These patterns fit an asynchronous, signed Drive-backed profile well:

- Rock/paper/scissors, hidden-order strategy turns, and secret draft choices.
- Coin flips, dice, draw-straws, turn order, and deterministic board-game
  setup from a jointly verified random seed.
- Guess-the-number games: players commit their guesses before the random round
  finalizes, then everyone learns the same winning number at reveal time.
- Tie breakers, randomized chores/meal/activity selection, and fair rotation
  of a shared responsibility among a pre-agreed eligible roster.
- Sealed proposals, blind preference collection, simultaneous estimates, and
  multi-party approval where a later reveal makes earlier choices auditable.
- Small non-anonymous raffles or bracket pairings where the eligible roster is
  fixed and signed before the randomness round begins.

They are not a replacement for real-time matchmaking, anonymous elections,
regulated lotteries, money escrow, trusted deadlines, or dispute resolution.
Those require properties a static asynchronous Drive protocol cannot honestly
provide.
