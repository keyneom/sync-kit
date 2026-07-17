import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  acceptSharedBackupOwnershipTransferV1,
  acceptSharingPublicKeyResponseV1,
  createSharedBackupOwnershipTransferProposalV1,
  createSharedBackupEnvelopeV1,
  createSharingInvitationV1,
  createSharingPublicKeyResponseV1,
  createWebCryptoSharingIdentity,
  decryptSharedBackupEnvelopeV1,
  sharingKeyFingerprint,
  verifySharedBackupEnvelopeV1,
  verifySharingInvitationV1,
  verifySharingPublicKeyResponseV1,
  type WebCryptoSharingIdentity,
} from "../src/sharing/web-crypto.js";
import {
  parseSharedBackupEnvelopeV1,
  SHARED_BACKUP_MAX_REVISION_ANCESTORS,
  type SharedBackupCodec,
  type SharedBackupEnvelopeV1,
  type SharedBackupOwnershipTransferV1,
  type SharingPublicKeyResponseV1,
  type SharingPublicKeyV1,
} from "../src/sharing/index.js";
import {
  createProtectedSharingIdentityV1,
  unlockProtectedSharingIdentityV1,
} from "../src/sharing/web-passkey.js";
import { base64UrlToBytes } from "../src/crypto/index.js";
import { copyBuffer } from "../src/crypto/runtime.js";

type Payload = {
  profile: string;
  count: number;
};

const codec: SharedBackupCodec<Payload> = {
  serialize: (value) => value,
  parse: (value) => {
    const candidate = value as Partial<Payload>;
    if (
      typeof candidate.profile !== "string" ||
      typeof candidate.count !== "number"
    ) {
      throw new TypeError("Invalid payload.");
    }
    return candidate as Payload;
  },
};

describe("shared-backup crypto", () => {
  it("round-trips passkey-protected, non-extractable sharing keys", async () => {
    const wrappingKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    const protectedIdentity = await createProtectedSharingIdentityV1(
      "fixture-app",
      {
        credentialId: "Y3JlZGVudGlhbA",
        rpId: "example.test",
        prfInput: new Uint8Array(32).fill(1),
        kdfSalt: new Uint8Array(32).fill(2),
      },
      wrappingKey,
    );
    const unlocked = await unlockProtectedSharingIdentityV1(
      protectedIdentity.record,
      wrappingKey,
    );

    expect(unlocked.publicKey).toEqual(protectedIdentity.identity.publicKey);
    expect(unlocked.encryptionPrivateKey.extractable).toBe(false);
    expect(unlocked.signingPrivateKey.extractable).toBe(false);
    expect(JSON.stringify(protectedIdentity.record)).not.toContain("\"d\":");
    await expect(
      createSharingInvitationV1(unlocked, {
        appId: "fixture-app",
        appFolderId: "folder",
        recipientDrivePermissionId: "permission",
        requestedGrants: [{ datasetId: "tasks", role: "viewer" }],
      }),
    ).resolves.toMatchObject({ appId: "fixture-app" });

    const wrongKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    await expect(
      unlockProtectedSharingIdentityV1(
        protectedIdentity.record,
        wrongKey,
      ),
    ).rejects.toMatchObject({ code: "key" });
  });

  it("unlocks the frozen ProtectedSharingIdentityV1 conformance fixture", async () => {
    // The same fixture the Kotlin ProtectedSharingIdentityTest unlocks, proving
    // a web-wrapped sharing identity round-trips byte-for-byte across platforms.
    const fixture = JSON.parse(
      await readFile(
        new URL(
          "../fixtures/sharing-v1/protected-identity.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as { wrappingKey: string; record: unknown; expected: { keyId: string } };
    const wrappingKey = await crypto.subtle.importKey(
      "raw",
      copyBuffer(base64UrlToBytes(fixture.wrappingKey)),
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const unlocked = await unlockProtectedSharingIdentityV1(
      fixture.record,
      wrappingKey,
    );
    expect(unlocked.publicKey.keyId).toBe(fixture.expected.keyId);
  });

  it("verifies and decrypts the frozen sharing-v1 WebCrypto fixture", async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL(
          "../fixtures/sharing-v1/webcrypto-owner-viewer.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as {
      payload: Payload;
      owner: {
        publicKey: SharingPublicKeyV1;
      };
      viewer: {
        publicKey: SharingPublicKeyV1;
        privateKeys: {
          encryption: JsonWebKey;
          signing: JsonWebKey;
        };
      };
      response: SharingPublicKeyResponseV1;
      envelope: SharedBackupEnvelopeV1;
    };
    const viewer: WebCryptoSharingIdentity = {
      publicKey: fixture.viewer.publicKey,
      encryptionPrivateKey: await crypto.subtle.importKey(
        "jwk",
        fixture.viewer.privateKeys.encryption,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      ),
      signingPrivateKey: await crypto.subtle.importKey(
        "jwk",
        fixture.viewer.privateKeys.signing,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
      ),
    };

    await expect(
      verifySharingPublicKeyResponseV1(fixture.response),
    ).resolves.toEqual(fixture.response);
    await expect(
      verifySharedBackupEnvelopeV1(fixture.envelope, crypto, {
        trustedOwnerKeyId: fixture.owner.publicKey.keyId,
      }),
    ).resolves.toEqual(fixture.envelope);
    await expect(
      verifySharedBackupEnvelopeV1(fixture.envelope, crypto, {
        trustedOwnerKeyId: fixture.viewer.publicKey.keyId,
      }),
    ).rejects.toMatchObject({ code: "authorization" });
    await expect(
      decryptSharedBackupEnvelopeV1(fixture.envelope, codec, viewer),
    ).resolves.toEqual(fixture.payload);
  });

  it("verifies the frozen Web-to-Kotlin ownership-transfer wire fixture", async () => {
    const fixture = JSON.parse(
      await readFile(
        new URL(
          "../fixtures/sharing-v1/ownership-transfer-wire.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as {
      payload: Payload;
      owner: { publicKey: SharingPublicKeyV1 };
      recipient: {
        publicKey: SharingPublicKeyV1;
        privateKeys: { encryption: JsonWebKey; signing: JsonWebKey };
      };
      before: SharedBackupEnvelopeV1;
      transfer: SharedBackupOwnershipTransferV1;
      after: SharedBackupEnvelopeV1;
    };
    const recipient: WebCryptoSharingIdentity = {
      publicKey: fixture.recipient.publicKey,
      encryptionPrivateKey: await crypto.subtle.importKey(
        "jwk",
        fixture.recipient.privateKeys.encryption,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      ),
      signingPrivateKey: await crypto.subtle.importKey(
        "jwk",
        fixture.recipient.privateKeys.signing,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
      ),
    };

    expect(fixture.after.accessControl.at(-1)?.ownershipTransfer).toEqual(
      fixture.transfer,
    );
    await expect(
      verifySharedBackupEnvelopeV1(fixture.after, crypto, {
        trustedOwnerKeyId: fixture.owner.publicKey.keyId,
      }),
    ).resolves.toEqual(fixture.after);
    await expect(
      decryptSharedBackupEnvelopeV1(fixture.after, codec, recipient, crypto, {
        trustedOwnerKeyId: fixture.owner.publicKey.keyId,
      }),
    ).resolves.toEqual(fixture.payload);
  });

  it("creates a signed, expiring multi-dataset invitation", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const invitation = await createSharingInvitationV1(
      owner,
      {
        appId: "fixture-app",
        appFolderId: "app-folder-1",
        exchangeId: "exchange-1",
        recipientDrivePermissionId: "recipient-permission",
        requestedGrants: [
          { datasetId: "a_b", role: "viewer" },
          { datasetId: "aB1", role: "writer" },
          { datasetId: "a-B", role: "viewer" },
          { datasetId: "Zx_", role: "writer" },
        ],
        createdAt: "2026-07-01T12:00:00.000Z",
        expiresAt: "2026-07-08T12:00:00.000Z",
      },
    );
    await expect(
      verifySharingInvitationV1(invitation, {
        now: () => new Date("2026-07-02T12:00:00.000Z"),
      }),
    ).resolves.toEqual(invitation);
    await expect(
      verifySharingInvitationV1(invitation, {
        now: () => new Date("2026-07-09T12:00:00.000Z"),
      }),
    ).rejects.toMatchObject({ code: "authorization" });
    expect(invitation.requestedGrants).toEqual([
      { datasetId: "Zx_", role: "writer" },
      { datasetId: "a-B", role: "viewer" },
      { datasetId: "aB1", role: "writer" },
      { datasetId: "a_b", role: "viewer" },
    ]);
  });

  it("exchanges a proof-of-possession public key and formats its fingerprint", async () => {
    const recipient = await createWebCryptoSharingIdentity();
    const response = await createSharingPublicKeyResponseV1(
      recipient,
      {
        appId: "fixture-app",
        exchangeId: "exchange-1",
        createdAt: "2026-07-01T12:00:00.000Z",
      },
    );

    await expect(verifySharingPublicKeyResponseV1(response)).resolves.toEqual(
      response,
    );
    expect(sharingKeyFingerprint(response.keyId)).toMatch(
      /^(?:[0-9a-f]{4}-){5}[0-9a-f]{4}$/u,
    );
    await expect(
      verifySharingPublicKeyResponseV1({
        ...response,
        exchangeId: "substituted",
      }),
    ).rejects.toMatchObject({ code: "key" });
  });

  it("turns a verified response into durable per-dataset acceptance records", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const invitation = await createSharingInvitationV1(owner, {
      appId: "fixture-app",
      appFolderId: "app-folder",
      exchangeId: "exchange-1",
      recipientDrivePermissionId: "recipient-permission",
      requestedGrants: [
        { datasetId: "profile", role: "viewer" },
        { datasetId: "tasks", role: "writer" },
      ],
      createdAt: "2026-07-01T12:00:00.000Z",
      expiresAt: "2026-07-08T12:00:00.000Z",
    });
    const response = await createSharingPublicKeyResponseV1(recipient, {
      appId: "fixture-app",
      exchangeId: "exchange-1",
      createdAt: "2026-07-01T12:01:00.000Z",
    });
    const grants = await acceptSharingPublicKeyResponseV1(
      invitation,
      response,
      {
        acceptedByKeyId: owner.publicKey.keyId,
        drivePermissionId: "recipient-permission",
        googleSubject: "google-subject",
        acceptedAt: "2026-07-01T12:02:00.000Z",
      },
      { now: () => new Date("2026-07-01T12:02:00.000Z") },
    );

    expect(grants).toHaveLength(2);
    expect(grants[1]).toMatchObject({
      datasetId: "tasks",
      participant: {
        publicKey: recipient.publicKey,
        role: "writer",
        accepted: {
          exchangeId: "exchange-1",
          drivePermissionId: "recipient-permission",
          googleSubject: "google-subject",
          acceptedByKeyId: owner.publicKey.keyId,
        },
      },
    });
    await expect(
      acceptSharingPublicKeyResponseV1(invitation, response, {
        acceptedByKeyId: owner.publicKey.keyId,
        drivePermissionId: "different-account",
      }),
    ).rejects.toMatchObject({ code: "authorization" });
  });

  it("encrypts one revision for an owner, writer, and viewer", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const writer = await createWebCryptoSharingIdentity();
    const viewer = await createWebCryptoSharingIdentity();
    const participants = [
      { publicKey: owner.publicKey, role: "owner" as const },
      { publicKey: writer.publicKey, role: "writer" as const },
      { publicKey: viewer.publicKey, role: "viewer" as const },
    ];
    const first = await createSharedBackupEnvelopeV1(
      { profile: "shared", count: 1 },
      codec,
      owner,
      {
        appId: "fixture-app",
        backupId: "backup-1",
        revisionId: "revision-1",
        createdAt: "2026-07-01T12:00:00.000Z",
        participants,
      },
    );

    await expect(verifySharedBackupEnvelopeV1(first)).resolves.toEqual(first);
    for (const identity of [owner, writer, viewer]) {
      await expect(
        decryptSharedBackupEnvelopeV1(first, codec, identity),
      ).resolves.toEqual({ profile: "shared", count: 1 });
    }

    const second = await createSharedBackupEnvelopeV1(
      { profile: "shared", count: 2 },
      codec,
      writer,
      {
        appId: "fixture-app",
        backupId: "backup-1",
        revisionId: "revision-2",
        createdAt: "2026-07-01T12:05:00.000Z",
        participants,
        previous: first,
      },
    );
    expect(second.parentRevisionId).toBe("revision-1");
    await expect(
      decryptSharedBackupEnvelopeV1(second, codec, viewer),
    ).resolves.toEqual({ profile: "shared", count: 2 });

    await expect(
      createSharedBackupEnvelopeV1(
        { profile: "shared", count: 3 },
        codec,
        viewer,
        {
          appId: "fixture-app",
          backupId: "backup-1",
          participants,
          previous: second,
        },
      ),
    ).rejects.toMatchObject({ code: "authorization" });
  });

  it("lets admins rotate recipients but prevents writers from changing access", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const admin = await createWebCryptoSharingIdentity();
    const writer = await createWebCryptoSharingIdentity();
    const viewer = await createWebCryptoSharingIdentity();
    const participants = [
      { publicKey: owner.publicKey, role: "owner" as const },
      { publicKey: admin.publicKey, role: "admin" as const },
      { publicKey: writer.publicKey, role: "writer" as const },
      { publicKey: viewer.publicKey, role: "viewer" as const },
    ];
    const first = await createSharedBackupEnvelopeV1(
      { profile: "shared", count: 1 },
      codec,
      owner,
      {
        appId: "fixture-app",
        backupId: "backup-1",
        participants,
      },
      { randomUUID: () => "revision-1" },
    );
    const withoutViewer = participants.filter(
      ({ publicKey }) => publicKey.keyId !== viewer.publicKey.keyId,
    );

    await expect(
      createSharedBackupEnvelopeV1(
        { profile: "shared", count: 2 },
        codec,
        writer,
        {
          appId: "fixture-app",
          backupId: "backup-1",
          participants: withoutViewer,
          previous: first,
        },
      ),
    ).rejects.toMatchObject({ code: "authorization" });

    const rotated = await createSharedBackupEnvelopeV1(
      { profile: "shared", count: 2 },
      codec,
      admin,
      {
        appId: "fixture-app",
        backupId: "backup-1",
        participants: withoutViewer,
        previous: first,
      },
    );
    expect(rotated.accessControl).toHaveLength(2);
    await expect(
      decryptSharedBackupEnvelopeV1(rotated, codec, viewer),
    ).rejects.toMatchObject({ code: "authorization" });
  });

  it("rotates an owner key with proofs from both old and new identities", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const replacement = await createWebCryptoSharingIdentity();
    const first = await createSharedBackupEnvelopeV1(
      { profile: "shared", count: 1 },
      codec,
      owner,
      {
        appId: "fixture-app",
        backupId: "backup-1",
        participants: [{ publicKey: owner.publicKey, role: "owner" }],
        revisionId: "owner-before-rotation",
      },
    );
    const rotated = await createSharedBackupEnvelopeV1(
      { profile: "shared", count: 1 },
      codec,
      replacement,
      {
        appId: "fixture-app",
        backupId: "backup-1",
        participants: [
          { publicKey: replacement.publicKey, role: "owner" },
        ],
        previous: first,
        keyRotation: { previousIdentity: owner },
        revisionId: "owner-after-rotation",
      },
    );

    await expect(
      verifySharedBackupEnvelopeV1(rotated, crypto, {
        trustedOwnerKeyId: owner.publicKey.keyId,
      }),
    ).resolves.toEqual(rotated);
    await expect(
      decryptSharedBackupEnvelopeV1(rotated, codec, replacement, crypto, {
        trustedOwnerKeyId: owner.publicKey.keyId,
      }),
    ).resolves.toEqual({ profile: "shared", count: 1 });
    await expect(
      decryptSharedBackupEnvelopeV1(rotated, codec, owner),
    ).rejects.toMatchObject({ code: "authorization" });
  });

  it("transfers ownership only after exact-head proofs from both identities", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const recipient = await createWebCryptoSharingIdentity();
    const accepted = {
      exchangeId: "exchange-1",
      drivePermissionId: "recipient-permission",
      acceptedAt: "2026-07-01T11:00:00.000Z",
      acceptedByKeyId: owner.publicKey.keyId,
    };
    const first = await createSharedBackupEnvelopeV1(
      { profile: "shared", count: 1 },
      codec,
      owner,
      {
        appId: "fixture-app",
        backupId: "profile",
        participants: [
          { publicKey: owner.publicKey, role: "owner" },
          { publicKey: recipient.publicKey, role: "writer", accepted },
        ],
        revisionId: "before-transfer",
      },
    );
    const proposal = await createSharedBackupOwnershipTransferProposalV1(
      [first],
      owner,
      {
        toKeyId: recipient.publicKey.keyId,
        previousOwnerRole: "admin",
        transferId: "transfer-1",
        createdAt: "2026-07-01T12:00:00.000Z",
        providerPermissionIds: { profile: "recipient-permission" },
        providerObjects: [
          {
            kind: "app-folder",
            fileId: "app-folder",
            providerPermissionId: "recipient-permission",
          },
          {
            kind: "exchanges-folder",
            fileId: "exchanges-folder",
            providerPermissionId: "recipient-permission",
          },
        ],
      },
    );
    await expect(
      acceptSharedBackupOwnershipTransferV1(
        {
          ...proposal,
          ownerProof: `${proposal.ownerProof.startsWith("A") ? "B" : "A"}${proposal.ownerProof.slice(1)}`,
        },
        [first],
        recipient,
      ),
    ).rejects.toMatchObject({ code: "crypto" });
    const transfer = await acceptSharedBackupOwnershipTransferV1(
      proposal,
      [first],
      recipient,
    );
    const transferred = await createSharedBackupEnvelopeV1(
      { profile: "shared", count: 1 },
      codec,
      recipient,
      {
        appId: "fixture-app",
        backupId: "profile",
        participants: [
          { publicKey: owner.publicKey, role: "admin" },
          { publicKey: recipient.publicKey, role: "owner", accepted },
        ],
        previous: first,
        ownershipTransfer: transfer,
        revisionId: "after-transfer",
      },
    );

    await expect(
      verifySharedBackupEnvelopeV1(transferred, crypto, {
        trustedOwnerKeyId: owner.publicKey.keyId,
      }),
    ).resolves.toEqual(transferred);
    await expect(
      decryptSharedBackupEnvelopeV1(transferred, codec, recipient, crypto, {
        trustedOwnerKeyId: owner.publicKey.keyId,
      }),
    ).resolves.toEqual({ profile: "shared", count: 1 });
    await expect(
      createSharedBackupEnvelopeV1(
        { profile: "shared", count: 2 },
        codec,
        owner,
        {
          appId: "fixture-app",
          backupId: "profile",
          participants: [
            { publicKey: owner.publicKey, role: "owner" },
            { publicKey: recipient.publicKey, role: "writer", accepted },
          ],
          previous: transferred,
        },
      ),
    ).rejects.toMatchObject({ code: "authorization" });

    await expect(
      createSharedBackupEnvelopeV1(
        { profile: "shared", count: 1 },
        codec,
        recipient,
        {
          appId: "fixture-app",
          backupId: "profile",
          participants: [
            { publicKey: owner.publicKey, role: "writer" },
            { publicKey: recipient.publicKey, role: "owner", accepted },
          ],
          previous: first,
          ownershipTransfer: transfer,
        },
      ),
    ).rejects.toMatchObject({ code: "authorization" });
  });

  it("rejects ciphertext and participant tampering before decryption", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const envelope = await createSharedBackupEnvelopeV1(
      { profile: "shared", count: 1 },
      codec,
      owner,
      {
        appId: "fixture-app",
        backupId: "backup-1",
        participants: [{ publicKey: owner.publicKey, role: "owner" }],
      },
    );
    const tamperedCiphertext: SharedBackupEnvelopeV1 = {
      ...envelope,
      ciphertext: mutate(envelope.ciphertext),
    };
    await expect(
      verifySharedBackupEnvelopeV1(tamperedCiphertext),
    ).rejects.toMatchObject({ code: "crypto" });

    const tamperedRole: SharedBackupEnvelopeV1 = {
      ...envelope,
      accessControl: envelope.accessControl.map((entry) => ({
        ...entry,
        participants: entry.participants.map((participant) => ({
          ...participant,
          role: "viewer",
        })),
      })),
    };
    await expect(
      verifySharedBackupEnvelopeV1(tamperedRole),
    ).rejects.toMatchObject({ code: "compatibility" });

    expect(() =>
      parseSharedBackupEnvelopeV1({
        ...envelope,
        parentRevisionId: "ancestor-256",
        revisionAncestors: Array.from(
          { length: SHARED_BACKUP_MAX_REVISION_ANCESTORS + 1 },
          (_, index) => `ancestor-${index}`,
        ),
      }),
    ).toThrow(/at most 256/u);
  });
});

function mutate(value: string): string {
  const last = value.at(-1);
  return `${value.slice(0, -1)}${last === "A" ? "B" : "A"}`;
}
