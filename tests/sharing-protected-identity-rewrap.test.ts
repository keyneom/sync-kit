import { describe, expect, it } from "vitest";
import type { WebPasskeyKeyMetadata } from "../src/keys/web-passkey/index.js";
import {
  createSharedBackupEnvelopeV1,
  decryptSharedBackupEnvelopeV1,
} from "../src/sharing/web-crypto.js";
import {
  createProtectedSharingIdentityV1,
  rewrapProtectedSharingIdentityV1,
  unlockProtectedSharingIdentityV1,
} from "../src/sharing/web-passkey.js";

const codec = {
  serialize: (value: { secret: string }) => value,
  parse: (value: unknown) => value as { secret: string },
};

async function wrappingKey(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function metadata(
  marker: number,
  credentialPublicKey?: JsonWebKey,
): WebPasskeyKeyMetadata {
  return {
    credentialId: `credential-${marker}`,
    rpId: "example.test",
    prfInput: new Uint8Array(32).fill(marker),
    kdfSalt: new Uint8Array(32).fill(marker + 10),
    ...(credentialPublicKey ? { credentialPublicKey } : {}),
  };
}

async function credentialPublicKey(): Promise<JsonWebKey> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return await crypto.subtle.exportKey("jwk", pair.publicKey);
}

describe("rewrapProtectedSharingIdentityV1", () => {
  it("keeps data encrypted to the identity readable under the replacement passkey", async () => {
    const oldKey = await wrappingKey();
    // A record from before credentialPublicKey was captured — the upgrade case.
    const original = await createProtectedSharingIdentityV1(
      "rewrap-app",
      metadata(1),
      oldKey,
    );
    expect(original.record.credentialPublicKey).toBeUndefined();

    // Something shared to this identity before the passkey is replaced.
    const envelope = await createSharedBackupEnvelopeV1(
      { secret: "written before the rewrap" },
      codec,
      original.identity,
      {
        appId: "rewrap-app",
        backupId: "vault",
        participants: [{ publicKey: original.record.publicKey, role: "owner" }],
      },
    );

    const replacementKey = await wrappingKey();
    const replacementPublicKey = await credentialPublicKey();
    const rewrapped = await rewrapProtectedSharingIdentityV1(
      original.record,
      oldKey,
      metadata(2, replacementPublicKey),
      replacementKey,
    );

    // Same identity: every dataset and keyring encrypted to it still applies.
    expect(rewrapped.record.publicKey).toEqual(original.record.publicKey);
    // New passkey: the record now names the replacement credential.
    expect(rewrapped.record.credentialId).toBe("credential-2");
    expect(rewrapped.record.credentialPublicKey).toEqual(replacementPublicKey);
    expect(rewrapped.record.prfInput).not.toBe(original.record.prfInput);
    expect(rewrapped.record.nonce).not.toBe(original.record.nonce);

    const reopened = await unlockProtectedSharingIdentityV1(
      JSON.parse(JSON.stringify(rewrapped.record)),
      replacementKey,
    );
    await expect(
      decryptSharedBackupEnvelopeV1(envelope, codec, reopened),
    ).resolves.toEqual({ secret: "written before the rewrap" });
  });

  it("locks the old passkey out of the new record and leaves the original intact", async () => {
    const oldKey = await wrappingKey();
    const original = await createProtectedSharingIdentityV1(
      "rewrap-app",
      metadata(1),
      oldKey,
    );
    const replacementKey = await wrappingKey();
    const rewrapped = await rewrapProtectedSharingIdentityV1(
      original.record,
      oldKey,
      metadata(2, await credentialPublicKey()),
      replacementKey,
    );

    await expect(
      unlockProtectedSharingIdentityV1(rewrapped.record, oldKey),
    ).rejects.toMatchObject({ code: "key" });
    // Until the caller persists the replacement, the original must still work.
    await expect(
      unlockProtectedSharingIdentityV1(original.record, oldKey),
    ).resolves.toMatchObject({ publicKey: original.record.publicKey });
  });

  it("requires the replacement registration to expose its public key", async () => {
    const oldKey = await wrappingKey();
    const original = await createProtectedSharingIdentityV1(
      "rewrap-app",
      metadata(1),
      oldKey,
    );
    await expect(
      rewrapProtectedSharingIdentityV1(
        original.record,
        oldKey,
        metadata(2),
        await wrappingKey(),
      ),
    ).rejects.toMatchObject({ code: "state" });
  });

  it("refuses to rewrap without the passkey that currently protects the identity", async () => {
    const original = await createProtectedSharingIdentityV1(
      "rewrap-app",
      metadata(1),
      await wrappingKey(),
    );
    await expect(
      rewrapProtectedSharingIdentityV1(
        original.record,
        await wrappingKey(),
        metadata(2, await credentialPublicKey()),
        await wrappingKey(),
      ),
    ).rejects.toMatchObject({ code: "key" });
  });
});
