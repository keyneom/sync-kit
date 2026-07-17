# Shared encrypted backups

This document defines the first sharing protocol for `sync-kit`. It extends the
package; it does not change or rewrite existing EasyBC or Family Chores v1
snapshots.

The concise, settled implementation decisions are in
`docs/sharing-implementation-handoff.md`. Use that file for continuation work;
this document provides the longer rationale and threat model.

For multi-profile UX, folder naming, join deeplinks, and what each application
must build versus what sync-kit provides, see
[consumer-responsibilities.md](consumer-responsibilities.md).

## Goal

An application can expose multiple encrypted backup files. Each file has its
own participants and whole-file access policy:

- an owner creates and administers the backup;
- an admin can change the cryptographic participant list;
- a writer can decrypt and publish a new signed revision;
- a viewer can decrypt but cannot publish an accepted revision.

Applications that need different access to different data must split that data
into separate backup files. Sharing v1 deliberately has no field-level policy.

When a profile needs a writable coordination channel that is separate from its
data files, use an encrypted shared control dataset. It records the signed
membership directory, explicit Picker/decrypt acknowledgements, and
hard-cutover migration status without giving every participant write access to
the data. See [sharing-control-datasets.md](sharing-control-datasets.md).

### Required deployment property: no trusted app backend

Sharing v1 must work in a static frontend with no application-owned trusted
server. Its required services are Google OAuth/Identity, Google Drive, browser
WebCrypto, and WebAuthn/passkeys. The package and wire protocol must not require
a server-held secret, refresh-token service, application database, certificate
issuer, permission service, or background worker.

The interactive client performs encryption, signature verification, key
exchange, access-history validation, and Drive permission reconciliation.
Google-signed identity material may be verified by the accepting client. The
accepted key and account provenance become durable only when an authorized
owner/admin signs them into the dataset access-control history.

Deployments may add a backend for unattended jobs, push notifications, or
operational automation. Such a backend is optional and must not become a
protocol trust root or be required for interoperability. A backendless app is
expected to sync and process exchanges when the user opens it and to request
fresh OAuth authorization or passkey presence when necessary.

## Correct boundary

There are four separate controls:

1. Google Picker or an Open-with action grants the app access to a specific
   Drive file or app folder.
2. Google Drive permissions decide who can read or modify that entire file.
3. Per-recipient wrapped content keys decide who can decrypt a revision.
4. A signed participant list decides whose revisions the app accepts.

All four must agree. Drive ACLs are not a substitute for cryptographic
authorization. A Drive writer can replace or delete bytes, so a signed
envelope protects integrity and authorship but cannot guarantee availability.

The existing `appDataFolder` store cannot be reused. Google prohibits sharing
files in `appDataFolder`. Shared backups and exchange files live in the normal,
user-visible `drive` space and use the non-sensitive `drive.file` scope.

`drive.file` is per-file access. The app can work with files it creates and
files the user explicitly opens or selects through Google Picker. The sharing
flow does not require the restricted full-Drive `drive` scope.

## User flow

### 1. Create the backup

The owner creates a sharing identity containing two non-extractable P-256
private keys:

- ECDH P-256 for receiving wrapped content keys;
- ECDSA P-256/SHA-256 for signing revisions and invitations.

The application must persist the opaque `CryptoKey` handles, normally in
IndexedDB, or provide a platform keystore implementation. A lost private key
cannot be reconstructed from the public backup.

Passkeys remain the user-unlock mechanism for existing private v1 snapshots.
They are not themselves recipient public keys: WebAuthn does not expose a
portable ECDH private key for encrypting data to another user. A complete
consumer should use a passkey to unlock or protect its local sharing identity,
then use the sharing identity for ECDH grants and revision signatures.

The owner creates the first envelope and a normal Drive file. The envelope has
one `owner` participant and one key grant. The app records at least:

- application ID;
- logical backup ID;
- Drive file ID;
- current verified revision ID;
- local sharing identity key ID.

This registry is application persistence and remains outside `sync-kit`.

### 2. Invite a recipient

The owner creates a signed invitation with:

- application and app-folder IDs;
- random exchange ID;
- invited account's stable Drive permission ID;
- one or more `{ datasetId, role }` grants, allowing different roles per
  dataset;
- creation time and optional expiry;
- the owner's public encryption/signing keys.

The owner shares the invitation file with the recipient. The Drive permission
request can send Google's normal sharing notification.

The recipient follows the notification and selects the shared app folder, or
opens the invitation directly. That action grants the app access to the
selected resource rather than the rest of Drive. The app persists the selected
folder ID.

### 3. Return a public key

The recipient verifies the signed invitation, creates an app-specific sharing
identity, and creates a public-key response bound to the invitation's
`exchangeId`.

The response is self-signed. This proves possession of the included signing
private key, but it does not prove the human identity behind that key. The
owner must bind the response to the intended recipient using the Drive sharing
identity and, for sensitive data, compare the displayed key fingerprint
through an authenticated second channel.

The recipient's app normally creates a new response file inside the shared
`exchanges/` folder. Directly sharing a standalone response file remains a
stricter alternative.

### 4. Grant access

On its next sync, the owner's app opens the response, verifies:

- response signature and key fingerprint;
- exact app ID and pending exchange ID;
- invitation expiry and requested dataset grants;
- intended Drive sender or an out-of-band fingerprint.

For each requested dataset, the owner adds the recipient public keys, role,
and accepted exchange/Drive provenance to a new revision. Each revision uses a
fresh random 256-bit content key and creates an ECDH/HKDF/AES-GCM key grant for
every current participant. It then signs the complete envelope.

Finally, the owner grants the matching Drive role on the backup file:

- `viewer` maps to Drive `reader`;
- `writer` maps to Drive `writer`;
- `admin` maps to Drive `writer`, plus the signed protocol role;
- `owner` remains the Drive file owner and the single sharing-v1 owner.

The recipient normally selects the shared app folder once. Subsequent sessions
reuse its stored folder ID and enumerate the app-created sync-kit children that
the recipient's Drive ACL permits.

Folder selection should not be treated as a recursive import mechanism for
arbitrary pre-existing Drive content. This protocol relies on children created
and tagged by the same app. A foreign file that was not created/opened for the
app may still need to be selected explicitly.

### 5. Read and write

Every reader:

1. parses the envelope and validates its complete structure;
2. verifies the hash-linked access-control history from its owner-signed
   genesis entry;
3. pins or checks the genesis owner key against the accepted invitation;
4. recomputes every participant key fingerprint;
5. verifies the content author's signature and current write role;
6. finds its own key grant;
7. derives the wrapping key with ECDH P-256 and HKDF-SHA-256;
8. unwraps the revision content key;
9. decrypts the AES-256-GCM payload and passes JSON to the consumer codec.

A writer creates a child revision whose `parentRevisionId` is the last verified
revision. A writer may change content but not participants. An owner or admin
may change participants. Only the owner can propose ownership transfer, and
the proposed owner must already be a verified participant in every dataset in
the signed profile manifest.

Each revision retains at most 256 recent ancestor IDs. A client whose last
verified revision falls outside that window cannot prove direct descent from
the head alone and must use the consumer's explicit fork merge/reject policy.

## Envelope model

Each revision is encrypted independently. The envelope contains public routing
metadata, a hash-linked access-control history, wrapped content keys,
ciphertext, and the content author's signature.

The first access-control entry is signed by the owner. A later entry contains
the hash of the complete previous entry and must be signed by an owner or admin
from that previous entry. This prevents a writer from promoting itself inside
the new participant list. An ownership-transfer entry instead requires the
current owner's signature over an exact, canonically ordered dataset/head/
provider-permission manifest, including the app-root and exchange folders,
and the proposed owner's countersignature. The
recipient publishes the new head, becomes owner, and the prior owner becomes
admin by default (or writer when explicitly selected).

For personal Google accounts, Drive separately requires the current owner to
mark the recipient `pendingOwner` and the recipient to accept ownership. This
applies separately to every dataset plus the app-root and exchange folders;
without the folders, the new owner could not manage later invitations. Drive
cannot atomically transfer multiple files, so the operation is resumable rather
than physically transactional: apps must treat it as incomplete until every
manifest object is transferred. The genesis owner pin remains unchanged and
verifiers follow the dual-signed owner transition from that trust root.

The built-in Google Drive controller currently implements this consumer-account
pending-owner flow. Google Workspace direct ownership transfer has different
domain policy and provider semantics and is not silently substituted.

A new recipient must verify the access-control genesis owner against the
owner key in the invitation. Existing participants persist that trusted owner
key with their local backup registry. Without this trust-on-first-use binding,
an entirely substituted history can be internally valid but belong to an
attacker.

Security-relevant values are canonicalized before signing. Payload AES-GCM AAD
binds the app ID, backup ID, revision ID, parent revision, timestamp, and
author. Each wrapped key is separately bound to the same backup/revision plus
its recipient and ephemeral ECDH key.

Public metadata is not secret. Drive and anyone with file access can observe
file names, timestamps, participant key IDs, role counts, revision IDs, and
ciphertext sizes. Applications must not put names, emails, schema content, or
other sensitive data in public fields.

## File topology and namespacing

New normal-Drive integrations default to a visible app-owned top-level folder:

```text
Sync Kit - <appId>/
  <backup-id>.sync-kit.json
  <another-backup-id>.sync-kit.json
```

`Sync Kit` is intentionally not named `.sync-kit`: Drive does not treat a
leading dot as hidden, so the dot would imply privacy it does not provide.
Consumers may override the name or explicitly supply a selected parent folder.

There is no common cross-app root by default. It provides little value and
would require separate OAuth applications to select the same folder. Share only
the backup, invitation, response, or limited exchange folders that need another
participant.

Use app-private `appProperties` to mark app-created objects:

```text
sync-kit-app-id = <consumer app ID>
sync-kit-kind = shared-backup | invitation | public-key-response
sync-kit-backup-id = <logical backup ID>
```

For mixed access, give participants `reader` access to the folder for
discovery, then grant direct `writer` access only on files they may modify.
Do not grant folder-level writer access when child files need different
policies: inherited writer permissions cannot be reduced on a child file.

This discoverable layout is the default:

| Object | Default Drive access |
| --- | --- |
| app folder | every app participant is `reader` |
| `exchanges/` | every app participant is `writer` |
| dataset file | inherits `reader`; selected collaborators receive direct `writer` |
| encryption grant | only participants allowed to decrypt that dataset |

The default intentionally accepts that every app participant can see dataset
filenames, timestamps, sizes, and ciphertext. Participants without a matching
cryptographic grant still cannot decrypt the dataset. This keeps ordinary app
integration and ACL reconciliation simple.

Google's limited-access subfolders are an exception to ordinary folder
inheritance. An owner can create a limited subfolder for one exchange, disable
inherited permissions, and directly grant only the intended recipient writer
access. This can provide a per-recipient response inbox under a shared
namespace. The package exposes `setFolderLimitedAccess`; consumers must check
the corresponding Drive capabilities because only permitted owners/organizers
can toggle the setting.

The default exchange topology can use one shared `exchanges/` folder under the
app folder. App participants receive `writer` on that folder while retaining
only `reader` on sibling data files unless a data-file ACL upgrades them.

Every response must be a new file created by the responding OAuth user. In My
Drive, that user becomes its owner. The inviter stores the stable Drive
permission ID returned when sharing the exchange folder, then requires:

- the response's sole `owners[].permissionId` to match;
- `lastModifyingUser.permissionId` to match;
- `sharingUser.permissionId`, when populated, to be consistent with the
  expected folder-sharing path;
- the signed app ID, exchange ID, and sharing-key proof to verify.

The package exposes `assertDriveFileProvenance` for these provider checks.
Another folder writer can modify or replace a response, but cannot preserve
the expected Google provenance, so the app rejects it. Writers can still
delete responses or flood the folder; this is an availability limitation, not
an impersonation path.

The exchange folder is an inbox and optional audit log, not the authoritative
key registry. The response files may be retained indefinitely for provenance,
support, or recovery; "accepted" responses do not need to be deleted.

After an owner or admin accepts a response, the public key and role are copied
into the dataset's signed, hash-linked access-control history. Every dataset
envelope therefore contains the durable authoritative participant keys needed
by any writer. Normal sync reads this authenticated state rather than trusting
mutable files in `exchanges/`.

When publishing a revision, a writer:

1. verifies the complete access-control history;
2. confirms its own current role permits writing;
3. generates a fresh random content key;
4. wraps that content key separately to every current owner, admin, writer, and
   viewer encryption key;
5. signs the complete revision.

Writers never trust unaccepted files from `exchanges/` and cannot change the
participant list. Only an owner/admin can append an access-control entry.
Removing or rotating a key creates another entry, and subsequent revisions no
longer grant the removed key access.

Standalone directly shared response files and per-recipient limited-access
folders remain stricter alternatives when an application does not accept that
availability risk.

Applications that require metadata isolation can opt into a strict layout:
keep the app folder private, share dataset files directly, or place sensitive
datasets inside limited-access subfolders. `sync-kit` exposes the required
per-file and limited-folder operations, but does not make every application
pay that management cost by default.

Drive provenance is provider-backed evidence, not a Google signature over the
public-key bytes. A stronger optional binding can use a verified Google ID
token whose nonce commits to the exchange ID and public-key ID. Consumers must
verify its signature, audience, issuer, expiry, and nonce, and use the stable
Google `sub` claim as the account identifier. Email is display metadata and can
change; it should not be the durable identity key.

Applications may skip folders entirely and keep a local registry of explicit
Drive file IDs. This is the simplest per-file `drive.file` model.

## Roles and limits

| Role | Decrypt | Sign content revision | Change crypto participants | Typical Drive role |
| --- | --- | --- | --- | --- |
| owner | yes | yes | yes | owner |
| admin | yes | yes | yes | writer |
| writer | yes | yes | no | writer |
| viewer | yes | no | no | reader |

Important limitations:

- A viewer who has decrypted data can copy it. Encryption cannot revoke
  knowledge already disclosed.
- Removing a participant rotates the content key for future revisions. The
  removed user can still decrypt revisions for which they retained a grant.
- A Drive writer can delete, corrupt, or roll back a file. Signatures make the
  attack detectable; they do not restore availability.
- A writer can disclose plaintext outside the app. Managed sharing objects use
  `writersCanShare=true` so a retained former-owner admin can reconcile Drive
  ACLs; ordinary writers can therefore also disclose ciphertext and metadata
  through Drive, but cannot create valid key grants or signed role changes.
- My Drive has no distinct application `admin` file role. The signed role can
  authorize participant changes, while provider ACL reconciliation additionally
  requires writer access on the relevant Drive object.
- Sharing identities are not the existing passkey-derived v1 snapshot key.
  Reusing that key would require exposing key material and would couple the new
  protocol to one browser credential.
- Key substitution remains possible only when a consumer permits an
  unverified response. Required account-binding mode verifies Drive provenance,
  a Google-signed account token, and a WebAuthn assertion over the same
  exchange/key challenge.
- The recipient must pin the invitation owner key when accepting a backup;
  self-consistent signatures do not establish first-contact identity.
- Apps must remember the last accepted revision ID to detect rollback or
  unexpected forks. A file's signature alone cannot prove it is the newest
  revision.

## Current package API

`@keyneom/sync-kit/sharing` exports protocol types, parsers, role checks, and
constants without browser dependencies.

`@keyneom/sync-kit/sharing/web-crypto` exports:

- `createWebCryptoSharingIdentity`;
- signed invitation creation and verification;
- public-key response creation and proof verification;
- shared-backup revision creation, verification, and decryption;
- human-readable key fingerprints.

`@keyneom/sync-kit/sharing/controller` adds headless multi-dataset operations,
signed ancestry, explicit fork policy, role/revocation changes, and dual-proof
key rotation. `/sharing/web-passkey` persists only passkey-encrypted private
keys, and `/sharing/account-binding` verifies Google/WebAuthn account binding.

`@keyneom/sync-kit/stores/google-drive` exports
`GoogleDriveFileStore` for normal Drive files, selected-folder listing,
user-visible file/folder creation, per-file reads/writes, notification-backed
sharing, permission removal, provenance metadata, and limited-access folders.
`/stores/google-drive/sharing` implements the managed folder/exchange layout
and conditional writes. `/stores/google-drive/picker` implements explicit
folder Picker and Open-with parsing.

`GoogleDriveFileSnapshotStore` defaults new private snapshots to a top-level
`Sync Kit - <appId>/` folder in normal Drive. The name and optional selected
parent are overrideable. Legacy `GoogleDriveSnapshotStore` remains the explicit
`appDataFolder` option.

`@keyneom/sync-kit/auth/google-web` exports `GOOGLE_DRIVE_FILE_SCOPE`.

The frozen synthetic WebCrypto conformance vector lives under
`fixtures/sharing-v1/`. Java independently consumes its private key, ECDH/HKDF
grant, AES-GCM ciphertext, and P-256 envelope signature.

The package does not own consumer UI, application persistence policy, schema
merge semantics, or background scheduling. Live Google validation and an
external consumer integration remain release gates.
