# sync-kit 0.4.5

Web parity for replacing the passkey on a sharing identity. Additive; no
existing signature, behavior, or format changes.

## `rewrapProtectedSharingIdentityV1`

`/sharing/web-passkey` now exports `rewrapProtectedSharingIdentityV1`, the web
counterpart of Kotlin's
`ProtectedSharingIdentityCrypto.rewrapWithReplacementCredential`. Android had it;
the web package did not.

It changes which passkey protects a sharing identity without changing the
identity. The keypair — and so its `keyId`, and every dataset and keyring
encrypted to it — is untouched. Two uses:

- **Moving to a new passkey** without losing access to anything shared.
- **Upgrading an old record.** Records created before `credentialPublicKey` was
  captured cannot support account binding, and until now web had no way to add
  it short of creating a new identity, which would have lost every share.

```ts
const identity = await unlockProtectedSharingIdentityV1(record, oldWrappingKey);
// ...register the replacement passkey, then:
const { record: replacement } = await rewrapProtectedSharingIdentityV1(
  record,
  oldWrappingKey,
  replacementMetadata, // must include credentialPublicKey
  replacementWrappingKey,
);
await store.save(replacement); // atomically; the original stays valid until then
```

Behavior matches Kotlin exactly: the replacement registration must expose its
ES256 public key (`state` otherwise), the current passkey must unlock the record
(`key` otherwise), and a changed `keyId` is rejected (`crypto`).

Web runtime keys are non-extractable, so this does not unlock and re-export the
identity. It decrypts the stored private-key bytes and re-seals them, through
the same sealing path `createProtectedSharingIdentityV1` uses — so a rewrapped
record is an ordinary V1 record, covered by the existing
`fixtures/sharing-v1/protected-identity.json` cross-platform fixture.

A regression test confirms that data encrypted to the identity before the rewrap
decrypts after it, and that the test fails if a rewrap mints a new identity.

## This is not recovery

A rewrap needs the passkey that currently protects the identity. It does nothing
for someone who has lost theirs. Recovery after a lost passkey is a separate,
open design question and is not in this release.

## CI

`check.yml` gains a `release-dry-run` job that runs both publish workflows'
exact setup and everything short of the upload, on every push and PR. The other
jobs rely on the Java and Android SDK the runner image happens to ship; the
publish workflows install their own. That divergence let a removed Android SDK
package break every release while CI stayed green.
