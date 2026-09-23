# Participant keys and recovery codes

Status: implemented in 0.5.0 on web and Android.

A participant in a shared dataset normally holds exactly one key: the sharing
identity their passkey protects. Lose the passkey and that identity is gone, and
with it everything other people have shared with them. This feature lets a
participant hold **additional keys** — most importantly a key sealed under a
printed **recovery code** — so a lost passkey is recoverable, including for data
someone else owns.

## It is opt-in at every level

Nothing changes for an app, a dataset, or a user that does not ask for it.

| Level | Control |
| --- | --- |
| Library | Additional keys exist only when an app calls the new APIs. Every existing call path behaves exactly as before. |
| App | An app that never calls them never produces them. |
| Dataset | An owner or admin enables it **per dataset** (`setParticipantKeysPolicy`). It is off by default. Until it is on, no participant can add a key to that dataset. |
| End user | The app decides who sees the toggle. Keyweb can let the owner choose per keyring whether that keyring accepts recovery codes. |

Turning the policy **off** removes every additional key from the dataset in the
same revision. Recovery codes stop working for that dataset immediately.

## Recovery codes

A recovery code is **128 random bits**, shown as 28 characters in seven groups
(`ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345`): 26 Crockford base32 characters for the
secret plus 2 check characters that catch typos. The library only ever
*generates* codes. `parseSharingRecoveryCode` rejects anything that is not a
well-formed generated code, so a user-chosen password cannot be used.

The code does not become a key directly. A recovery key is an ordinary sharing
identity — a random P-256 encryption keypair and a random P-256 signing keypair —
whose private keys are **sealed under the code**:

```text
wrapping key = HKDF-SHA256(ikm = code secret, salt = random 32 bytes,
                           info = "sync-kit participant recovery key v1")
sealed       = AES-256-GCM(wrapping key, packed private keys,
                           aad = canonical header binding appId and keyId)
```

The sealed private keys are stored **inside every data file that grants that
key access**, next to its public key.

### Why seal it in the file rather than derive the key from the code

Deriving the keypair deterministically from the code was the first option
considered. It is equally secure, but it cannot be done with the platform crypto
alone: WebCrypto and Android's standard crypto API only generate keys randomly or
import complete ones, and neither exposes the elliptic-curve arithmetic needed to
turn a seed into a P-256 public key. It would make a third-party curve library
sync-kit's first runtime dependency, on both platforms.

Sealing the key into each file gives the same recoverability without that
dependency:

| | Sealed in the file (chosen) | Derived from the code |
| --- | --- | --- |
| **To recover you need** | The code and **any one** data file | The code and any one data file |
| **Works from an offline copy of a single file** | Yes — the file carries the sealed key | Yes |
| **Depends on Drive, the control ledger, or a companion file** | No | No |
| **Resistance to guessing** | 2^128 — every guess costs an HKDF plus an AES-GCM check | 2^128 — every guess costs a curve multiplication |
| **New dependency** | None | A curve library on web and Android |

The two are equally recoverable because of a fact that holds for both: a file is
only readable by a key it grants access to, and every file that grants the
recovery key also carries it. There is no file the derived design could open that
the sealed design cannot.

### Security relative to a passkey

| Threat | Passkey | Recovery code |
| --- | --- | --- |
| Guessing | Infeasible | Infeasible at 128 bits |
| Phishing | Resistant — bound to the relying party | Vulnerable — it can be typed into a fake page |
| Theft | Requires the device plus a biometric or PIN | **Whoever holds the code is the participant**, until it is removed |

That last row is the cost of recovery working without the device. Two properties
reduce it:

- **Recovery is visible.** Using a recovery key to replace a lost passkey writes a
  signed key rotation into every dataset it touches. An app can alert on it.
- **Recovery is revocable.** Removing the recovery key from each dataset ends it.
  A removed key cannot be re-added from its old authorization.

Every co-participant can see a participant's sealed recovery key and could try to
guess the code offline. At 128 bits that is not a practical attack, which is why
codes must be generated and never chosen.

## Protocol

This extends the V1 shared-backup envelope. A dataset that has never enabled the
policy is byte-for-byte unchanged.

### Version signal

An envelope whose access-control history has **ever** used any field below
carries `schemaVersion: 2`, and never returns to 1. Readers before 0.5.0 reject
version 2 as incompatible — they fail closed instead of silently dropping the
extra keys' access on their next write, which is what an unaware reader would
otherwise do. Apps must not let an owner enable the policy until every
participant runs a version that reads it.

### Fields on an access-control entry

```ts
participantKeysPolicy?: "enabled";          // absent = disabled
additionalKeys?: SharedBackupAdditionalKeyV1[];   // sorted by keyId
removedAdditionalKeys?: SharedBackupKeyRemovalV1[]; // proofs for removals in this entry
keyRotation.authorizedByKeyId?: string;     // rotation authorized by an additional key
keyRotation.authorization?: string;
```

An additional key is a public key plus the proof that its participant (the
**principal**) authorized it:

```ts
type SharedBackupAdditionalKeyV1 = SharingPublicKeyV1 & {
  principalKeyId: string;   // the participant this key belongs to
  purpose: "recovery" | "device";
  addedByKeyId: string;     // the principal key that signed the addition
  addition: string;         // signature by addedByKeyId
  possession: string;       // signature by this key: proves the holder has it
  sealedPrivateKeys?: SharedBackupSealedKeyV1; // present for recovery codes
};
```

Signed statements are app-scoped rather than dataset-scoped, so one signed
operation applies to every dataset the participant is in:

| Operation | Signed statement | Signed by |
| --- | --- | --- |
| Add a key | `{kind: "sync-kit-participant-key-addition", appId, principalKeyId, addedByKeyId, key, purpose, sealedPrivateKeys?}` | an existing key of the principal, and the new key |
| Remove a key | `{kind: "sync-kit-participant-key-removal", appId, keyId, addition}` | any key of the key's current principal |
| Replace the lost passkey | `{kind: "sync-kit-participant-key-rotation", appId, fromKeyId, to}` | an additional key of `fromKeyId`, and the new key |

### Rules

Every reader enforces these while walking the access-control history from its
first entry:

1. **Policy.** Only an owner or admin may change `participantKeysPolicy`. While it
   is absent, `additionalKeys` must be empty.
2. **Adding.** A new additional key needs a valid `addition` signature from the
   principal's primary key or one of its existing additional keys, and a valid
   `possession` signature from the new key. **This holds even when an owner or
   admin writes the entry** — nobody can attach a key to someone else.
3. **Removing.** An owner or admin may remove any additional key. Anyone else must
   include a removal statement signed by a key of that principal. An addition that
   was removed can never be re-added from the same signature.
4. **Grouping.** Every additional key's principal must be a current participant.
   Removing a participant removes all of their keys in the same entry. A key's
   role is always its principal's role, so changing a participant's role covers
   every one of their keys.
5. **Replacing a lost passkey.** An additional key may authorize replacing its
   principal's primary key with a new one. The new key takes the same role and
   acceptance; the principal's other additional keys move to the new primary. For
   an owner this is also the owner change, and the dataset's trust root (its first
   owner) is unaffected.
6. **Carrying.** Operations are signed by the principal, not by the entry's
   author, so any participant who can write the file may carry them in. That is
   how a viewer, who cannot write, gets a key applied.
7. **Limits.** An additional key may author an access-control entry only when that
   entry changes nothing except its own principal's keys. It can never author a
   data revision. Each principal may hold at most 8 additional keys, and no key ID
   may appear twice.
8. **Access.** Every revision grants its content key to every participant and
   every additional key.

### When a key takes effect

Each revision re-encrypts to exactly the keys listed in it, so a new key protects
a file only from that file's next write onward. Writers apply their own keys to
every dataset immediately. A viewer's keys wait until a writer carries them —
automatically, as described in the next section.

**"Recovery is set up" is therefore not the same as "recovery protects this
file."** `participantKeyCoverage` reports, per dataset, whether a key is present
in the current revision, so an app can show the truth: *"Recovery protects 3 of 4
shared keyrings — 1 is waiting for its owner to sync."*

### Carrying a viewer's keys automatically

A viewer cannot write the data it views, but a profile's **control dataset** is
different: its participants are writers even where they only view the data (see
`docs/sharing-control-datasets.md`). So a viewer applies its own key operations
to the control dataset directly — adding a recovery key, removing one, or
replacing a lost key with a recovery rotation.

`replicateParticipantKeys({ sourceDatasetId, datasetIds })` then carries them
onward. Any writer's or admin's app runs it — for example on every sync, with the
control dataset as the source — and it replays the source's participant-signed
operations, in order, into each dataset that app can write:

- Each key goes in as it was first added, so its signatures verify anywhere.
- Signed removals and recovery rotations follow in their original order, since a
  later operation may be signed by a key an earlier rotation introduced.
- Anything already reflected in a dataset is skipped, so it is safe to run
  repeatedly.
- A dataset whose owner has not enabled participant keys is left alone — the
  per-keyring decision stays the owner's.

It needs no new control-ledger event, so readers of the ledger are unaffected.
Owner or admin removals carry no participant signature and are not carried; an
owner or admin removes a key in each dataset directly. After a rotation lands in
the control dataset, the owner's existing `synchronizeMembers` call picks up the
new key in the ledger's member list.

## API

The same operations exist on both platforms.

| Step | Web (`@keyneom/sync-kit/sharing/participant-keys`) | Android (`com.keyneom.synckit.sharing`) |
| --- | --- | --- |
| Generate a code | `generateSharingRecoveryCode()` | `ParticipantKeys.generateRecoveryCode()` |
| Validate typing | `isSharingRecoveryCodeWellFormed(code)` | `ParticipantKeys.isRecoveryCodeWellFormed(code)` |
| Seal a recovery key | `createSharingRecoveryKeyV1({ appId, code })` | `ParticipantKeys.createRecoveryKey(appId, code)` |
| Sign an addition | `createParticipantKeyAdditionV1(...)` | `ParticipantKeys.createAddition(...)` |
| Sign a removal | `createParticipantKeyRemovalV1(...)` | `ParticipantKeys.createRemoval(...)` |
| Sign a lost-key rotation | `createAuthorizedKeyRotationV1(...)` | `ParticipantKeys.createAuthorizedRotation(...)` |
| Open from one file | `openSharingRecoveryKeyFromEnvelopeV1({ code, envelope })` | `ParticipantKeys.openRecoveryKeyFromEnvelope(code, envelope)` |

`SharedBackupController` applies them to a dataset: `setParticipantKeysPolicy`,
`addParticipantKeys`, `removeParticipantKeys`, `rotateWithAdditionalKey`,
`openRecoveryKey`, `getDatasetParticipantKeys`, and `participantKeyCoverage`.
`replicateParticipantKeys` carries operations from one dataset to others, and
`rotateLocalKey` replaces a key you still hold across your datasets.

## Recovering

1. The user enters their recovery code.
2. `openRecoveryKey(datasetId, code)` unseals the recovery key from any one
   dataset — on a fresh device, before anything is registered.
3. The user registers a new passkey, creating a new sharing identity.
4. `createAuthorizedKeyRotation` signs "replace my lost key with this one" with
   the recovery key, and `rotateWithAdditionalKey` applies it to each dataset.
   The lost key is gone from every dataset that is rewritten.
5. The recovery key stays in place, now attached to the new key, for next time.

A writer or owner completes all of this alone, passing the replacement and
recovery identities as `recovery`. A viewer recovers the control dataset alone —
it is a writer there — and writers' `replicateParticipantKeys` carries the
rotation into the data it views.

## Verified across platforms

`fixtures/sharing-v1/participant-keys.json` is a web-written history — policy
enabled, a viewer's recovery key carried in by the owner, a recovery-authorized
rotation, and a removal. Android verifies every revision, opens the recovery key
from its code, and decrypts. `npm run parity:recovery:check` runs the reverse:
Android writes a history and the web package verifies it and opens the
Android-sealed recovery key. Both run in `npm run check`.

## Private snapshots

Private data — one user's own backup, not shared — has its own recovery code,
through snapshot v2. See `docs/snapshot-recovery.md`.
