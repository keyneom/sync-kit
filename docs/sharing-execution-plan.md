# Shared-backup execution plan

This plan adds sharing without changing the existing private snapshot protocol.
Existing v1 fixtures, profiles, filenames, AAD, HKDF labels, and Android
compatibility remain frozen.

Implementation decisions and lifecycle defaults are authoritative in
`docs/sharing-implementation-handoff.md`.

## Phase S0: protocol and threat model

- [x] Make static-frontend operation without an application-owned trusted
      backend a normative package and protocol objective.
- [x] Separate Drive discovery, Drive ACLs, decryption grants, and signed write
      authority.
- [x] Record that `appDataFolder` objects cannot be shared.
- [x] Select `drive.file` plus Picker/Open-with for explicit file or app-folder
      consent.
- [x] Define whole-file roles and the split-file strategy for finer access.
- [x] Document metadata leakage, key substitution, revocation, rollback,
      availability, and writer-exfiltration limits.

Exit gate: documentation does not imply that encryption, Drive ACLs, or a
shared folder provide guarantees they cannot enforce, and no required protocol
step depends on an application-owned server.

## Phase S1: provider-neutral protocol surface

- [x] Add browser-independent sharing types, constants, parsers, and role
      checks under `/sharing`.
- [x] Define signed invitations and proof-of-possession public-key responses.
- [x] Define a versioned envelope with one owner, participant roles, per-
      recipient key grants, revision lineage, and an author signature.
- [x] Bind participant changes through a hash-linked access-control history
      signed by a prior owner/admin, with optional trusted-owner pinning.
- [x] Make each dataset envelope self-contained with the authoritative current
      participant public keys so every writer can create all required grants.
- [x] Keep application schemas and codecs outside the package.
- [x] Freeze a synthetic sharing-v1 WebCrypto fixture.
- [ ] Consume the sharing-v1 fixture on another platform before claiming
      native compatibility.

Exit gate: malformed participants, grants, roles, algorithms, keys, and
envelopes are rejected before application parsing.

## Phase S2: WebCrypto implementation

- [x] Generate separate non-extractable P-256 ECDH and ECDSA private keys.
- [x] Derive stable SHA-256 public-key IDs and display fingerprints.
- [x] Use fresh AES-256-GCM content keys per revision.
- [x] Wrap content keys per participant with ephemeral ECDH P-256,
      HKDF-SHA-256, and AES-256-GCM.
- [x] Sign the complete canonical envelope.
- [x] Require a previous authorized writer for child revisions.
- [x] Limit participant changes to the prior owner/admin.
- [x] Rotate grants when a participant is removed.
- [x] Add viewer/writer/admin, tampering, expiry, and removal tests.
- [ ] Add native implementations and consume the same fixtures before claiming
      web/native sharing compatibility.

Exit gate: recipients decrypt the same revision, viewers cannot create accepted
revisions, writers cannot change access, and tampering fails.

## Phase S3: Google Drive per-file transport

- [x] Export the non-sensitive `drive.file` scope.
- [x] Add a normal-Drive store without changing `GoogleDriveAppDataStore`.
- [x] Default new file-backed snapshots to an app-owned top-level
      `Sync Kit - <appId>/` folder, with name and optional parent overrides.
- [x] Default shared layouts to app-folder discovery, writable exchanges, and
      per-dataset writer upgrades while keeping strict metadata isolation
      opt-in.
- [x] Create user-visible files and optional namespace folders.
- [x] Filter accessible files by selected parent and app properties.
- [x] Read, update, and delete an explicitly opened file ID.
- [x] Create per-file reader/writer permissions with Drive notifications.
- [x] Default app-created files to `writersCanShare=false`.
- [x] Remove a direct permission by ID.
- [x] Support limited-access subfolders for isolated recipient exchange
      inboxes.
- [x] Validate My Drive key-response ownership, sharing user, and last modifier
      against the invited account's stable Drive permission ID.
- [x] Add a Google Picker adapter and Open-with state parsing.
- [x] Add permission listing/update and controller-driven ACL reconciliation.
- [x] Add optional Google-account key attestation using an ID-token nonce bound
      to the exchange and key IDs.
- [ ] Validate Picker and account attestation against live Google services.

Exit gate: a consumer can complete the flow with access only to app-created
objects beneath a selected app folder or explicitly selected files; the
restricted full-Drive scope is not required.

## Phase S4: orchestration and persistence

- [x] Add passkey-encrypted sharing identity records, non-extractable runtime
      key imports, an application store contract, and an IndexedDB store.
- [x] Define a local registry for multiple app profiles/backups and last
      verified revision IDs.
- [x] Implement a sharing controller for pending invitations/responses,
      revision serialization, fork detection, and ACL reconciliation.
- [x] Add optimistic concurrency using Drive ETag/`If-Match` preconditions so two
      writers cannot silently overwrite one another.
- [x] Keep revisions in one Drive file for sharing v1, with a signed parent and
      conditional replacement.
- [ ] Validate ETag preconditions and permission reconciliation against live
      Google Drive rather than mocks.
- [x] Add signed ancestry, known-rollback rejection, and an explicit
      consumer merge/reject fork contract.
- [x] Add dual-proof key rotation, including owner-key replacement without
      transferring the owner role.
- [ ] Design ownership transfer as a separate future protocol.

Exit gate: concurrent writers, stale clients, rollback, forks, and partial ACL
updates have deterministic outcomes.

## Phase S5: consumer adoption

- [ ] Add Picker/Open-with and identity persistence to one web consumer.
- [ ] Present invitation sender, role, file, and key fingerprint before
      acceptance.
- [ ] Support multiple named backups/profiles without mixing local state.
- [ ] Verify read-only UI prevents writes and reports rejected revisions.
- [ ] Split a real consumer schema into at least two files and prove per-file
      permissions.
- [x] Consume and authenticate/decrypt the sharing fixture from Java before
      making a Java compatibility statement.
- [x] Execute exchange and decrypt flows from packed npm and pnpm artifacts.
- [ ] Run packed-artifact integration tests in every adopting external
      consumer.

Exit gate: one consumer completes owner/invite/response/grant/read/write/revoke
flows using only per-file Drive access, and a second platform consumes the
frozen wire fixtures before cross-platform release.

## Phase S5.1: control datasets and topology cutover

- [x] Add an encrypted, per-cohort control dataset with individually signed
      membership, migration, acknowledgement, and close events.
- [x] Require a control dataset to match the sharing envelope's pinned owner.
- [x] Support one invitation that grants application datasets plus a
      protocol-owned control dataset with different codecs.
- [x] Make acknowledgement validation compare required target file IDs before
      allowing an ordinary migration close.
- [x] Document the initial multi-select Picker enrollment, hard-cutover
      requirement, metadata tradeoffs, and consumer-owned payload transforms.
- [ ] Validate the exact multi-select Picker and post-accept control-file flow
      against live Google Drive with two accounts.
- [ ] Add application-facing orchestration for creating target datasets from a
      consumer-supplied topology transform; keep that transform and ACL policy
      in the consumer.

Exit gate: a consumer can enroll a control file in its first invitation, detect
missed target-file selections, collect all required acknowledgements, and hold
old-file retirement when any acknowledgement is absent.

## Deferred: commit/reveal choices and verifiable multi-party randomness

- [ ] Add canonical, domain-separated action/input commitments and signed
      reveal verification.
- [ ] Add deterministic multi-party randomness derivation with rejection
      sampling for unbiased bounded results.
- [ ] Model unrevealed contributions as an explicit blocked/abandoned round;
      do not treat Drive timestamps as an enforceable timeout.
- [ ] Add application-neutral round-status APIs while leaving game rules,
      eligibility, user experience, and any forfeit policy to consumers.

See [sharing-control-datasets.md](sharing-control-datasets.md) for the proposed
protocol, fairness assumptions, and appropriate backend-free use cases.

## Phase S6: background change detection

- [x] Document Tier A (Drive metadata) vs Tier B (local reminders) boundaries.
- [x] Add `SharingSyncCheckpoint` and `SharingNotificationEvent` (JSON schema).
- [x] Add metadata-only `SharingChangeDetector` on npm `/sharing`.
- [x] Add opt-in `IndexedDbAuthorizationCache` and `bindSharingPoll` (web).
- [x] Add `SharingSyncWorker` skeleton on Android.
- [ ] Validate WorkManager poll against mocked Drive in instrumented tests.

Exit gate: apps can notify users of pending key responses and dataset head
changes without background decrypt or signing.

## Phase S7: Android sharing port

- [x] Add Kotlin sharing protocol parsers and P-256 crypto matching the fixture.
- [x] Add `GoogleDriveFileStore` and `GoogleDriveSharedBackupTransport`.
- [x] Add `SharedBackupController` parity with npm headless API.
- [x] Add join URL helpers and folder naming utilities.
- [ ] Live Google Drive validation on Android (ETag, permissions, provenance).
- [ ] One native consumer completes end-to-end sharing from a published artifact.

Exit gate: Android matches npm sharing behavior on frozen fixtures and one
live Drive smoke path.

## Release posture

The current build completes the package implementation through S4, including
Picker, protected identity, account attestation, concurrency, ancestry/forks,
rotation, Java fixture consumption, and packed-artifact execution. It remains
unreleased until live Google validation and one external consumer integration
are complete.
