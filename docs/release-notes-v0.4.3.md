# sync-kit 0.4.3

Documentation only — no signature, behavior, or format change. Published so the
contracts reach `.d.ts` and KDoc where consumers actually read them. Reported in
keyneom/sync-kit#8 from Keyweb's integration.

## `KeyProvider.unlock` returns the derived content key

The interface carried no documentation at all. Passkey-backed providers run the
PRF ceremony and then the envelope's KDF over its `kdfSalt` before returning, so
the result is ready to use — but nothing said so. A consumer derived from it a
second time and held `KDF(KDF(secret, salt), salt)` against the browser's
`KDF(secret, salt)`.

That failure does not look like a key-derivation mismatch. It looks like
Credential Manager returned the wrong credential, which sent the consumer
chasing Digital Asset Links instead. Both `create` and `unlock` now say what
they return, on both platforms.

## The single-account multi-device identity pattern is named

`PasskeyProtectedSharingIdentityProvider`,
`DriveAppDataProtectedSharingIdentityStore`, and
`MigratingProtectedSharingIdentityStore` ship and are tested, but appeared
nowhere in the README or `docs/` by name. A consumer who did not find them
wrapped the sharing identity in a recovery-code-derived key instead, stranding
it: a browser holding the passkey and the whole dataset still could not act on
a shared keyring, because the identity it could reach was not the identity the
keyring was encrypted to.

`docs/consumer-responsibilities.md` gains a section naming the three, and states
the anti-pattern — do not wrap the sharing identity in an application-owned
secret.

## `SharedBackupControllerCodec.fingerprint` self-recursion

In Kotlin, `override fun fingerprint(value: T) = fingerprint(value)` inside an
`object :` body calls itself, because the member shadows a top-level function of
the same name. `syncDataset` calls `fingerprint` on every write, and the
resulting `StackOverflowError` is an `Error`, not an `Exception`, so a
consumer's `catch (e: Exception)` never sees it — one consumer's writes failed
silently for six days. The KDoc now warns and names the fixes.

## Known gaps, not addressed here

Both need API work and are not in this release:

- **No web equivalent of `ProtectedSharingIdentityCrypto.rewrapWithReplacementCredential`.**
  Android can re-wrap an identity under a replacement credential; the web
  package cannot, so adding a second lock to an existing identity, or wrapping
  a new passkey around an identity recovered another way, is Android-only.
- **`addDatasetParticipant` requires `emailAddress` on both platforms.** A
  purely cryptographic recipient — a recovery or escrow key with no Drive
  account — cannot be added, because the transport share is not separable from
  the cryptographic grant.

## Real-device status

A consumer reports the Credential Manager assertion path succeeding on a Pixel
with `get_login_creds` present: the ceremony completed and
`AndroidPasskeyKeyProvider.unlock` returned bytes. The **failure** path added in
0.4.2 — whether a missing asset link surfaces as `NoCredentialException` rather
than something else — remains unverified on hardware by anyone. The execution
checklist gate stays open.
