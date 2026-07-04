# Version 1 compatibility contract

This document freezes the persisted v1 behavior extracted from the live EasyBC
and Family Chores applications. The machine-readable values live in
`fixtures/v1/profiles.json`.

## EasyBC

- Drive filename: `easybc-sync-v1.json`
- Envelope schema: `1`
- Algorithm label: `AES-256-GCM+HKDF-SHA-256`
- AES-GCM nonce/tag: 12 bytes / 128 bits
- Authenticated data: UTF-8 `easy-bc-sync-envelope-v1`
- HKDF: SHA-256, a per-passkey 32-byte salt, UTF-8 info
  `easy-bc-cloud-content-key-v1`
- PRF input: 32 random bytes, persisted as unpadded base64url (parsers reject
  other lengths; historical one-byte test vectors were updated to 32 bytes)
- Compression: gzip only when its byte length is smaller than plaintext;
  omission of `compression` means plaintext JSON
- Passkey: RP ID `keyneom.github.io` in the native application, ES256,
  discoverable credential, required user verification, exact credential ID in
  `allowCredentials`

The web application derives the RP ID from its current hostname. The native
Android implementation fixes it to `keyneom.github.io`. A consumer must reject
an envelope whose RP ID does not match the domain it is operating for.

## Family Chores

- Drive filename: `family-chores-sync-v1.json`
- Envelope schema and algorithm label: same as EasyBC
- AES-GCM nonce/tag: 12 bytes / 128 bits
- Authenticated data: UTF-8 `family-chores-sync-envelope-v1`
- HKDF info: UTF-8 `family-chores-cloud-content-key-v1`
- KDF salt and PRF input: 32 random bytes each
- Compression: none in v1
- Passkey: the EasyBC settings with application names changed to
  `Family Chores` and `Family Chores encrypted sync`

## Envelope shape

Both applications persist:

```json
{
  "schemaVersion": 1,
  "algorithm": "AES-256-GCM+HKDF-SHA-256",
  "compression": "gzip",
  "credentialId": "unpadded-base64url",
  "rpId": "keyneom.github.io",
  "prfInput": "unpadded-base64url",
  "kdfSalt": "unpadded-base64url",
  "nonce": "unpadded-base64url",
  "ciphertext": "unpadded-base64url-ciphertext-and-tag",
  "updatedAt": "ISO-8601 timestamp"
}
```

`compression` is optional and currently valid only for EasyBC. The AES-GCM tag
is appended to the ciphertext by WebCrypto and Java's `AES/GCM/NoPadding`.
Unknown JSON fields are tolerated by the native EasyBC reader.

## Fixture provenance and regeneration

`scripts/generate-v1-fixtures.mjs` contains no application data. It:

1. freezes the exact vectors already consumed by EasyBC web and Android tests;
2. decrypts those vectors to freeze their complete expected payloads;
3. creates a deterministic Family Chores vector from the live, uncommitted
   implementation using fixed synthetic bytes;
4. creates authenticated failure vectors for tampering, wrong context,
   malformed envelopes, wrong secrets, and invalid gzip content.

Regenerate with:

```sh
node scripts/generate-v1-fixtures.mjs
```

The source revisions inspected on 2026-06-29 were:

- EasyBC `e6d3250af204f0e1a8b8fe25fd276b24a70f42b3`
- Family Chores base `60ef3428b8613b756de42668d04b5fe88f0af157`,
  with `sync/` and `tests/sync/` still uncommitted
- Keynote `a22978fcfe0efdccf64352f11d49e61510163fe0`

Do not regenerate existing fixture ciphertext as part of ordinary refactors.
Add a new fixture when a compatibility source intentionally changes.
