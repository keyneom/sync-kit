# Shared backups: implementation handoff

This is the authoritative implementation brief for shared encrypted backups.
It preserves existing private v1 snapshots and does not migrate current
consumers automatically.

## Non-negotiable package objective

The complete sharing flow must work from a static frontend without an
application-owned trusted backend. Use Google Identity Services, Google Drive,
WebCrypto, and WebAuthn/passkeys directly from the client. Do not require a
server-held secret, refresh-token service, application database, certificate
signer, authorization service, or background worker.

An optional backend may provide unattended jobs, notifications, or operational
automation, but it must not become a protocol trust root or interoperability
requirement. Backendless operation is interactive: sync occurs while the app
is open, and token renewal or passkey use may require user presence.

## Settled defaults

- Use normal My Drive storage with the non-sensitive `drive.file` scope.
- Keep `appDataFolder` as an explicit legacy/private-storage option.
- Create one top-level folder per app automatically. Fallback name:
  `Sync Kit - <appId>`; consumers should pass a friendly app-specific name.
- The owner sees no Picker. A recipient selects the shared app folder once;
  persist its Drive folder ID and reuse it for app-created/tagged children.
  Do not treat this as recursive authorization for arbitrary foreign files.
- Expose headless APIs and typed state. Consumers own all UI.
- Treat Drive file IDs and signed IDs as authoritative. Names are presentation.

## Default Drive layout

```text
<App Name> Sync/                         reader: every app participant
  exchanges/                            writer: every app participant
    <exchangeId>-invitation.json
    <exchangeId>-<keyId>-response.json
  <datasetId>.sync-kit.json              inherited reader; direct writers vary
```

Recommended `appProperties`:

```text
sync-kit-app-id
sync-kit-kind = app-root | exchange-folder | invitation | key-response | dataset
sync-kit-dataset-id
sync-kit-protocol = sharing-v1
```

Every app participant can observe dataset filenames, sizes, timestamps, and
ciphertext. Cryptographic grants, not folder visibility, control decryption.
This metadata exposure is accepted by default.

Strict metadata isolation is opt-in: keep the app folder private and share
files directly, or put sensitive datasets in limited-access subfolders.

## Drive and cryptographic permissions

| Object | Drive ACL | Cryptographic rule |
| --- | --- | --- |
| app folder | participant = reader | discovery only |
| `exchanges/` | participant = writer; `writersCanShare=false` | every artifact is untrusted until verified |
| dataset | viewer = inherited reader; writer/admin/owner = direct writer | signed dataset ACL determines decrypt/write/admin authority |

Drive permissions propagate downward, not sideways. Writing to `exchanges/`
does not grant write access to sibling datasets.

The Drive owner performs permission reconciliation by default. Drive has no
separate application-admin role. An app admin may authorize a cryptographic ACL
change, but the Drive owner might still need to apply its matching Drive ACL.

## Key exchange

1. Owner/admin creates a signed invitation with app ID, exchange ID, requested
   dataset grants, folder ID, creation time, and expiry.
2. The intended Google account creates a new response file in `exchanges/`.
3. Validate the signed app/exchange IDs and sharing-key proof.
4. For My Drive, require:
   - exactly one owner;
   - `owners[0].permissionId` equals the invited Drive permission ID;
   - `lastModifyingUser.permissionId` equals that owner;
   - `sharingUser`, when present, is consistent with the sharing path.
5. Optionally verify a Google-account/passkey key-binding attestation.
6. Owner/admin appends the accepted key and role to each selected dataset's
   signed access-control history.

The stable invitation format should use
`requestedGrants: { datasetId, role }[]`; one app-level sharing identity can be
accepted into several datasets with different roles. The implementation now
uses that shape and signs the app folder ID plus invited Drive permission ID.

The exchange folder is an inbox and optional audit log. It is never the
authoritative registry. Writers ignore unaccepted exchange files.

Another writer cannot preserve the expected Drive provenance after replacing
or modifying a response. Writers can still delete responses or flood the
folder. Treat that as a detectable availability limitation.

### Passkey/account binding

Do not derive an asymmetric sharing key directly from passkey PRF bytes.
Generate a sharing ECDH/signing identity and certify the binding:

1. Hash the app ID, exchange ID, Google `sub`, passkey credential ID, and
   sharing public keys.
2. Use that hash as the WebAuthn assertion challenge.
3. Bind the same hash into a verified Google ID-token nonce.
4. Verify WebAuthn RP ID, origin, challenge, credential signature, Google JWT
   signature, audience, issuer, expiry, and nonce.
5. Use Google `sub` as the durable account ID. Email is display metadata.

For a backendless deployment, the accepting client verifies the Google-signed
identity token and WebAuthn assertion directly, then an authorized owner/admin
signs the minimal accepted provenance into dataset access-control history. Do
not retain the raw Google ID token after validation.

A deployment may optionally perform the same verification on its own backend
and return a minimal certificate. The package must not require or privilege
that path over client verification.

This binding is implemented in `/sharing/account-binding` and integrated
through optional controller hooks. Required-mode acceptance rejects a missing
binding or verifier. The verified response artifact is deleted before dataset
updates so its raw Google ID token is not retained. Live browser validation
against Google remains required before claiming the flow production-ready.

## Authoritative keys and dataset writes

Each dataset envelope contains its own hash-linked, signed access-control
history with current participant roles and public keys. This makes datasets
independent and gives every writer the keys needed for the next revision.

For every write:

1. Verify the trusted genesis owner and complete ACL chain.
2. Verify the current content signature and parent revision.
3. Confirm the local key currently has `owner`, `admin`, or `writer`.
4. Merge through the consumer codec.
5. Generate a fresh random 256-bit content key.
6. Wrap it separately for every current owner/admin/writer/viewer key.
7. Encrypt once with AES-256-GCM and sign the complete revision.
8. Update Drive with an ETag/`If-Match` precondition.

Only a prior owner/admin may append an ACL entry. A writer cannot accept keys
or change roles. Owner transfer is not part of sharing v1.

Removing a key prevents future grants but cannot revoke plaintext or old
revisions already received. Key rotation is remove-old/add-new.

## Exchange lifecycle

Recommended defaults, all consumer-configurable:

- Invitation validity: 7 days.
- Pending responses: process until the invitation expires.
- Accepted/rejected/expired artifacts: retain for audit during early validation
  so exchange history can be inspected when testing live flows. After a long
  clean run, switch to post-accept cleanup or a short retention window (see
  `docs/execution-checklist.md` deferred recovery/audits items).
- Raw Google ID tokens: delete the response artifact immediately after
  successful account-binding verification (current controller behavior). Do not
  retain the raw token.
- Accepted public keys and roles: retain indefinitely in dataset ACL history.
- Minimal acceptance record: retain in ACL history with exchange ID, key ID,
  Drive permission ID, Google `sub` when verified, role, actor, and timestamp.

Cleanup is operational hygiene, not a security boundary. Retaining public-key
responses longer is intentional while audits matter more than inbox size;
normal sync must never depend on them.

## Concurrency and rollback

The controller and Drive transport now:

- read an ETag and send it through `If-Match` on every dataset replacement;
- reject unexpected `parentRevisionId`;
- retain the last verified revision ID locally;
- never silently accept last-writer-wins;
- pin the genesis owner key from the accepted invitation.
- carry signed revision ancestry, reject known rollback, and invoke a
  consumer-supplied merge/reject policy for divergent valid heads.
- retain the 256 most recent signed ancestor IDs. A controller that has been
  offline beyond that window treats the unrecognized head as a possible fork
  and requires the same explicit consumer merge/reject policy.

Before production use, validate conditional updates against live Drive. The
consumer owns its merge function and explicit fork decision callback; without
an affirmative `merge`, a divergent head is rejected.

Signatures detect corruption and unauthorized authorship. They do not prevent
deletion, rollback, or denial of service.

## Required headless API

The next implementation should expose operations equivalent to:

```text
ensureStorage
listDatasets
createDataset
syncDataset
inviteParticipant
listExchanges
submitKeyResponse
acceptKeyResponse
setDatasetRole
revokeDatasetKey
rotateLocalKey
reconcileDrivePermissions
```

Return typed operation state and actionable errors. Do not display Google UI
except unavoidable OAuth consent/account selection and the recipient's
one-time folder Picker.

## Current implementation

Implemented:

- `/sharing` protocol types, parsing, roles, and access history;
- `/sharing/web-crypto` identities, invitations, key responses, grants,
  signatures, verification, and decryption;
- multi-dataset invitations and signed acceptance provenance;
- `/sharing/controller` headless dataset, invitation, response, role, and
  revocation orchestration;
- `/sharing/web-passkey` passkey-encrypted identity records and an IndexedDB
  ciphertext store;
- `/sharing/account-binding` Google JWT and WebAuthn verification over one
  exchange/key challenge;
- signed revision ancestry, rollback detection, consumer-controlled fork
  merge/reject, and dual-proof owner/writer key rotation;
- normal-Drive app folders, per-file reads/writes/sharing, limited folders,
  and provenance validation;
- `/stores/google-drive/sharing` managed hierarchy, exchange transport,
  permissions, and ETag/`If-Match` writes;
- `/stores/google-drive/picker` folder selection and Open-with state parsing;
- synthetic WebCrypto sharing fixture and package tests;
- Java consumption of the sharing fixture and packed-package exchange/decrypt
  execution;
- unchanged private v1 compatibility.

Release blockers:

- live Google Drive validation of conditional writes and permission
  reconciliation;
- live Google OAuth, Picker, and account-binding browser validation;
- integration into an external consumer with its real UI and persistence.

Do not publish the sharing surface as stable until these blockers are closed.
