# Private snapshot recovery (snapshot v2)

Status: implemented in 0.5.0 on web and Android.

A private snapshot is one user's encrypted backup. In v1 its content key is
derived directly from the passkey, so losing the passkey loses the backup.
Snapshot **v2** holds the content key under **locks** — the passkey, and
optionally a generated recovery code — so the backup survives a lost passkey.
This is the v2 envelope planned in `docs/implementation-plan.md`, with an explicit
`appId` and a canonical authenticated header.

For data shared with other people, see `docs/participant-keys.md` instead.

## Nothing changes unless you opt in

v1 is untouched: its format, reader, and writer are byte-for-byte what they were,
and v1 snapshots stay readable indefinitely. A profile opts in explicitly, in two
steps — reading first, writing second — because a device that cannot read v2 is
locked out of a snapshot the moment it becomes v2:

```ts
const profile = defineV1CompatibilityProfile({
  // ...your existing profile...
  readVersions: [1, 2], // step 1: ship this to every device first
  writeVersion: 1,      // step 2, later: 2 makes new snapshots v2
});
```

Android takes the same `readVersions` and `writeVersion` on
`V1CompatibilityProfile`. The rules, enforced on both platforms:

- `readVersions` must include 1, and `writeVersion` must be one of them.
- **Ordinary sync keeps a snapshot's own version.** It never upgrades v1 to v2
  and never downgrades v2 to v1.
- A snapshot changes version only through an explicit call:
  `setRecoveryCode` (which upgrades to v2), or `migrateVersion`, which is
  reversible. Moving back to v1 removes the recovery code.
- A device whose profile does not read v2 rejects a v2 snapshot as
  incompatible instead of misreading it.

## Using a recovery code

```ts
const code = await generateRecoveryCode(createWebCryptoBackend());
// Show it once. Whoever holds it can open the backup.
await snapshot.setRecoveryCode(code);  // unlocks with the passkey; upgrades to v2

// Later, on a new device, with the passkey lost:
await snapshot.recover(code);          // registers a new passkey and re-locks
```

`recover` opens the snapshot with the code, merges it with local state, registers
a new passkey through your key provider, and locks the snapshot under it. The
recovery code keeps working afterwards. `setRecoveryCode(null)` removes it, and
calling `setRecoveryCode` with a new code replaces the old one.

On Android: `RecoveryCodes.generate()`, then `SnapshotSyncController.setRecoveryCode`,
`recover`, and `migrateVersion`.

Codes are the same format as participant recovery codes — 128 random bits, 28
characters with 2 check characters that catch typos — and are only ever generated.
A typo is reported as a typo, distinct from a code that simply does not match.

## Format

```ts
{
  schemaVersion: 2,
  appId,                  // must match the profile, or the snapshot is rejected
  algorithm: "AES-256-GCM+HKDF-SHA-256",
  compression?: "gzip",
  credentialId, rpId, prfInput, kdfSalt,       // the passkey, exactly as in v1
  contentSalt,
  passkeyKey: { nonce, wrappedKey },           // content key under the passkey
  recoveryKey?: { kdfSalt, nonce, wrappedKey }, // content key under the code
  nonce, ciphertext, updatedAt,
}
```

- The **content key** is `HKDF-SHA256(random 32 bytes, contentSalt,
  "sync-kit snapshot content key v2")`. The random bytes stay the same across
  writes, which is what lets ordinary sync keep the recovery lock valid without
  the code.
- The **passkey lock** wraps those bytes under the key your key provider already
  derives from the passkey — so existing key providers unlock v2 unchanged.
- The **recovery lock** wraps them under
  `HKDF-SHA256(code secret, its own salt, "sync-kit snapshot recovery key v2")`.
- The **whole header** — every field but `nonce` and `ciphertext`, rebuilt from
  the known fields on both platforms — is authenticated as the payload's AAD,
  together with the profile's `aad`. Changing any header field, including
  `updatedAt` or a lock, makes the snapshot fail to decrypt.

Everything uses only operations every `CryptoBackend` already provides, plus
SHA-256 for the code's check characters. `CryptoBackend.sha256` is optional so
existing backends keep compiling; the WebCrypto backend provides it, and
recovery-code operations report a configuration error on a backend without it.

## Security

The recovery code has the same properties as a participant recovery code — see
the security table in `docs/participant-keys.md`. It is as strong as the passkey
against guessing, and weaker against theft: whoever holds it can open the backup
until it is removed. Anyone with access to the stored snapshot can try to guess
the code offline, which at 128 random bits is not a practical attack.

## Verified across platforms

`fixtures/v2/snapshot-recovery.json` holds web-written v2 snapshots — plain, with
a recovery code, re-locked under a new passkey after recovery, and migrated back
to v1. Android decrypts each one with its passkey secret and, where present, the
recovery code. `npm run parity:recovery:check` runs the reverse: Android writes a
v2 snapshot with a recovery code and the web package opens it both ways. The
v1 parity check is unchanged and still passes.
