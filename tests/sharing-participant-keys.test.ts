import { describe, expect, it } from "vitest";
import {
  parseSharedBackupEnvelopeV1,
  sharedBackupAdditionalKeys,
  sharedBackupParticipants,
  type SharedBackupEnvelopeV1,
  type SharingRole,
} from "../src/sharing/index.js";
import {
  createAuthorizedKeyRotationV1,
  createParticipantKeyAdditionV1,
  createParticipantKeyRemovalV1,
  createSharingRecoveryKeyV1,
  generateSharingRecoveryCode,
  isSharingRecoveryCodeWellFormed,
  openSharingRecoveryKeyFromEnvelopeV1,
  parseSharingRecoveryCode,
} from "../src/sharing/participant-keys.js";
import {
  createSharedBackupEnvelopeV1,
  createWebCryptoSharingIdentity,
  decryptSharedBackupEnvelopeV1,
  verifySharedBackupEnvelopeV1,
  type SharedBackupParticipantKeyChanges,
  type WebCryptoSharingIdentity,
} from "../src/sharing/web-crypto.js";

const APP = "participant-keys-app";
const DATASET = "vault";
const codec = {
  serialize: (value: { secret: string }) => value,
  parse: (value: unknown) => value as { secret: string },
};

function inputs(envelope: SharedBackupEnvelopeV1) {
  return sharedBackupParticipants(envelope).map(({ role, accepted, ...publicKey }) => ({
    publicKey,
    role,
    ...(accepted ? { accepted } : {}),
  }));
}

async function write(
  author: WebCryptoSharingIdentity,
  previous: SharedBackupEnvelopeV1 | undefined,
  secret: string,
  extra: {
    participants?: { publicKey: WebCryptoSharingIdentity["publicKey"]; role: SharingRole }[];
    participantKeys?: SharedBackupParticipantKeyChanges;
  } = {},
): Promise<SharedBackupEnvelopeV1> {
  return await createSharedBackupEnvelopeV1({ secret }, codec, author, {
    appId: APP,
    backupId: DATASET,
    participants: extra.participants ?? (previous ? inputs(previous) : []),
    ...(previous ? { previous } : {}),
    ...(extra.participantKeys ? { participantKeys: extra.participantKeys } : {}),
  });
}

/** Owner and a viewer, with the dataset's participant-keys policy on. */
async function sharedVault() {
  const owner = await createWebCryptoSharingIdentity();
  const viewer = await createWebCryptoSharingIdentity();
  const writer = await createWebCryptoSharingIdentity();
  const genesis = await write(owner, undefined, "v1", {
    participants: [
      { publicKey: owner.publicKey, role: "owner" },
      { publicKey: viewer.publicKey, role: "viewer" },
      { publicKey: writer.publicKey, role: "writer" },
    ],
  });
  const enabled = await write(owner, genesis, "v2", {
    participantKeys: { policy: true },
  });
  return { owner, viewer, writer, genesis, enabled };
}

async function recoveryKeyFor(principal: WebCryptoSharingIdentity) {
  const code = await generateSharingRecoveryCode();
  const recovery = await createSharingRecoveryKeyV1({ appId: APP, code });
  const addition = await createParticipantKeyAdditionV1({
    appId: APP,
    principalKeyId: principal.publicKey.keyId,
    authorizer: principal,
    key: recovery.identity,
    purpose: "recovery",
    sealedPrivateKeys: recovery.sealedPrivateKeys,
  });
  return { code, identity: recovery.identity, addition };
}

describe("participant keys", () => {
  it("leaves datasets that never opt in on schemaVersion 1", async () => {
    const { genesis } = await sharedVault();
    expect(genesis.schemaVersion).toBe(1);
    expect(genesis.accessControl.at(-1)).not.toHaveProperty("participantKeysPolicy");
  });

  it("marks a dataset schemaVersion 2 once enabled, so older readers fail closed", async () => {
    const { enabled } = await sharedVault();
    expect(enabled.schemaVersion).toBe(2);
    expect(() => parseSharedBackupEnvelopeV1({ ...enabled, schemaVersion: 1 })).toThrow(
      /must declare schemaVersion 2/,
    );
  });

  it("lets a viewer recover a lost passkey from the code and one data file", async () => {
    const { owner, viewer, enabled } = await sharedVault();
    const recovery = await recoveryKeyFor(viewer);
    // A viewer cannot write, so the owner carries the viewer's signed addition.
    const withRecovery = await write(owner, enabled, "v3", {
      participantKeys: { add: [recovery.addition] },
    });
    expect(sharedBackupAdditionalKeys(withRecovery)).toHaveLength(1);

    // The viewer loses their passkey. The code and this one file are enough.
    const offlineCopy = JSON.parse(JSON.stringify(withRecovery));
    const opened = await openSharingRecoveryKeyFromEnvelopeV1({
      code: recovery.code,
      envelope: offlineCopy,
    });
    await expect(
      decryptSharedBackupEnvelopeV1(offlineCopy, codec, opened.identity),
    ).resolves.toEqual({ secret: "v3" });

    // Replace the lost key; the owner carries the recovery-signed rotation.
    const replacement = await createWebCryptoSharingIdentity();
    const rotation = await createAuthorizedKeyRotationV1({
      appId: APP,
      fromKeyId: viewer.publicKey.keyId,
      authorizer: opened.identity,
      replacement,
    });
    const rotated = await write(owner, withRecovery, "v4", {
      participantKeys: { rotation },
    });
    const participants = sharedBackupParticipants(rotated);
    expect(participants.some((p) => p.keyId === viewer.publicKey.keyId)).toBe(false);
    expect(participants.find((p) => p.keyId === replacement.publicKey.keyId)?.role).toBe("viewer");
    // The recovery key now belongs to the replacement key.
    expect(sharedBackupAdditionalKeys(rotated)).toMatchObject([
      { principalKeyId: replacement.publicKey.keyId },
    ]);
    await expect(decryptSharedBackupEnvelopeV1(rotated, codec, replacement)).resolves.toEqual({
      secret: "v4",
    });
    // The lost key can no longer read new revisions.
    await expect(decryptSharedBackupEnvelopeV1(rotated, codec, viewer)).rejects.toMatchObject({
      code: "authorization",
    });
  });

  it("lets a writer recover alone: the recovery key signs the access change", async () => {
    const { writer, enabled } = await sharedVault();
    const recovery = await recoveryKeyFor(writer);
    const withRecovery = await write(writer, enabled, "v3", {
      participantKeys: { add: [recovery.addition] },
    });
    const replacement = await createWebCryptoSharingIdentity();
    const rotation = await createAuthorizedKeyRotationV1({
      appId: APP,
      fromKeyId: writer.publicKey.keyId,
      authorizer: recovery.identity,
      replacement,
    });
    const rotated = await write(replacement, withRecovery, "v4", {
      participantKeys: { rotation, accessAuthor: recovery.identity },
    });
    await expect(verifySharedBackupEnvelopeV1(rotated)).resolves.toBeDefined();
    await expect(decryptSharedBackupEnvelopeV1(rotated, codec, replacement)).resolves.toEqual({
      secret: "v4",
    });
  });

  it("lets an owner recover without changing the dataset's trust root", async () => {
    const { owner, enabled } = await sharedVault();
    const recovery = await recoveryKeyFor(owner);
    const withRecovery = await write(owner, enabled, "v3", {
      participantKeys: { add: [recovery.addition] },
    });
    const replacement = await createWebCryptoSharingIdentity();
    const rotation = await createAuthorizedKeyRotationV1({
      appId: APP,
      fromKeyId: owner.publicKey.keyId,
      authorizer: recovery.identity,
      replacement,
    });
    const rotated = await write(replacement, withRecovery, "v4", {
      participantKeys: { rotation, accessAuthor: recovery.identity },
    });
    expect(sharedBackupParticipants(rotated).find((p) => p.role === "owner")?.keyId).toBe(
      replacement.publicKey.keyId,
    );
    // Clients pin the first owner; that pin still verifies the recovered dataset.
    await expect(
      verifySharedBackupEnvelopeV1(rotated, globalThis.crypto, {
        trustedOwnerKeyId: owner.publicKey.keyId,
      }),
    ).resolves.toBeDefined();
  });

  it("lets a participant remove its own key, and never re-add it from the old signature", async () => {
    const { owner, viewer, enabled } = await sharedVault();
    const recovery = await recoveryKeyFor(viewer);
    const withRecovery = await write(owner, enabled, "v3", {
      participantKeys: { add: [recovery.addition] },
    });
    const removal = await createParticipantKeyRemovalV1({
      appId: APP,
      authorizer: viewer,
      key: recovery.addition,
    });
    const removed = await write(owner, withRecovery, "v4", {
      participantKeys: { remove: [removal] },
    });
    expect(sharedBackupAdditionalKeys(removed)).toHaveLength(0);
    await expect(
      write(owner, removed, "v5", { participantKeys: { add: [recovery.addition] } }),
    ).rejects.toThrow(/cannot be re-added/);
  });

  it("removes a key after a rotation, using the key as it was originally added", async () => {
    const { owner, viewer, enabled } = await sharedVault();
    const recovery = await recoveryKeyFor(viewer);
    const withRecovery = await write(owner, enabled, "v3", {
      participantKeys: { add: [recovery.addition] },
    });
    const replacement = await createWebCryptoSharingIdentity();
    const rotated = await write(owner, withRecovery, "v4", {
      participantKeys: {
        rotation: await createAuthorizedKeyRotationV1({
          appId: APP,
          fromKeyId: viewer.publicKey.keyId,
          authorizer: recovery.identity,
          replacement,
        }),
      },
    });
    // The app kept the addition it made; the rotation has since moved the key.
    const removal = await createParticipantKeyRemovalV1({
      appId: APP,
      authorizer: replacement,
      key: recovery.addition,
    });
    const removed = await write(owner, rotated, "v5", { participantKeys: { remove: [removal] } });
    expect(sharedBackupAdditionalKeys(removed)).toHaveLength(0);
  });

  it("removes every additional key when an owner turns the policy off", async () => {
    const { owner, viewer, enabled } = await sharedVault();
    const recovery = await recoveryKeyFor(viewer);
    const withRecovery = await write(owner, enabled, "v3", {
      participantKeys: { add: [recovery.addition] },
    });
    const disabled = await write(owner, withRecovery, "v4", {
      participantKeys: { policy: false },
    });
    expect(sharedBackupAdditionalKeys(disabled)).toHaveLength(0);
    expect(disabled.schemaVersion).toBe(2);
    await expect(
      openSharingRecoveryKeyFromEnvelopeV1({ code: recovery.code, envelope: disabled }),
    ).rejects.toMatchObject({ code: "key" });
  });

  it("keeps additional keys through ordinary writes", async () => {
    const { owner, writer, viewer, enabled } = await sharedVault();
    const recovery = await recoveryKeyFor(viewer);
    const withRecovery = await write(owner, enabled, "v3", {
      participantKeys: { add: [recovery.addition] },
    });
    // A plain write with no participant-key changes, as syncDataset makes.
    const next = await write(writer, withRecovery, "v4");
    expect(next.accessControl).toEqual(withRecovery.accessControl);
    await expect(decryptSharedBackupEnvelopeV1(next, codec, recovery.identity)).resolves.toEqual({
      secret: "v4",
    });
  });

  describe("rejects", () => {
    it("a policy change by a non-admin", async () => {
      const { writer, genesis } = await sharedVault();
      await expect(write(writer, genesis, "v2", { participantKeys: { policy: true } })).rejects.toThrow(
        /owner or admin/,
      );
    });

    it("additions while the policy is off", async () => {
      const { owner, viewer, genesis } = await sharedVault();
      const recovery = await recoveryKeyFor(viewer);
      await expect(
        write(owner, genesis, "v2", { participantKeys: { add: [recovery.addition] } }),
      ).rejects.toMatchObject({ code: "state" });
    });

    it("an owner attaching a key to someone else", async () => {
      const { owner, viewer, enabled } = await sharedVault();
      const attackerKey = await createWebCryptoSharingIdentity();
      const forged = await createParticipantKeyAdditionV1({
        appId: APP,
        principalKeyId: viewer.publicKey.keyId,
        authorizer: owner, // not the viewer
        key: attackerKey,
        purpose: "recovery",
      });
      await expect(
        write(owner, enabled, "v3", { participantKeys: { add: [forged] } }),
      ).rejects.toThrow(/not authorized by its participant/);
    });

    it("a sealed recovery key swapped after signing", async () => {
      const { owner, viewer, enabled } = await sharedVault();
      const recovery = await recoveryKeyFor(viewer);
      const other = await createSharingRecoveryKeyV1({
        appId: APP,
        code: await generateSharingRecoveryCode(),
      });
      const swapped = { ...recovery.addition, sealedPrivateKeys: other.sealedPrivateKeys };
      await expect(
        write(owner, enabled, "v3", { participantKeys: { add: [swapped] } }),
      ).rejects.toThrow(/not authorized by its participant/);
    });

    it("a writer removing someone else's key without their signature", async () => {
      const { owner, writer, viewer, enabled } = await sharedVault();
      const recovery = await recoveryKeyFor(viewer);
      const withRecovery = await write(owner, enabled, "v3", {
        participantKeys: { add: [recovery.addition] },
      });
      await expect(
        write(writer, withRecovery, "v4", {
          participantKeys: { remove: [{ keyId: recovery.addition.keyId }] },
        }),
      ).rejects.toThrow(/Only an owner, an admin, or the key's own participant/);
    });

    it("a rotation authorized by someone else's recovery key", async () => {
      const { owner, viewer, writer, enabled } = await sharedVault();
      const viewersRecovery = await recoveryKeyFor(viewer);
      const withRecovery = await write(owner, enabled, "v3", {
        participantKeys: { add: [viewersRecovery.addition] },
      });
      const hijack = await createWebCryptoSharingIdentity();
      const rotation = await createAuthorizedKeyRotationV1({
        appId: APP,
        fromKeyId: writer.publicKey.keyId, // the viewer's key cannot replace the writer
        authorizer: viewersRecovery.identity,
        replacement: hijack,
      });
      await expect(
        write(owner, withRecovery, "v4", { participantKeys: { rotation } }),
      ).rejects.toThrow(/authorized key rotation is not valid/);
    });

    it("a writer carrying a rotation it has no authority for", async () => {
      const { owner, viewer, writer, enabled } = await sharedVault();
      const viewersRecovery = await recoveryKeyFor(viewer);
      const withRecovery = await write(owner, enabled, "v3", {
        participantKeys: { add: [viewersRecovery.addition] },
      });
      const rotation = await createAuthorizedKeyRotationV1({
        appId: APP,
        fromKeyId: owner.publicKey.keyId,
        authorizer: viewersRecovery.identity,
        replacement: await createWebCryptoSharingIdentity(),
      });
      await expect(
        write(writer, withRecovery, "v4", { participantKeys: { rotation } }),
      ).rejects.toThrow(/authorized key rotation is not valid/);
    });

    it("an additional key authoring a data revision", async () => {
      const { owner, viewer, enabled } = await sharedVault();
      const recovery = await recoveryKeyFor(viewer);
      const withRecovery = await write(owner, enabled, "v3", {
        participantKeys: { add: [recovery.addition] },
      });
      await expect(write(recovery.identity, withRecovery, "v4")).rejects.toMatchObject({
        code: "authorization",
      });
    });
  });
});

describe("recovery codes", () => {
  it("round-trips and tolerates formatting", async () => {
    const code = await generateSharingRecoveryCode();
    expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){6}$/);
    const secret = await parseSharingRecoveryCode(code);
    expect(secret).toHaveLength(16);
    expect(await isSharingRecoveryCodeWellFormed(code.toLowerCase().replace(/-/g, " "))).toBe(true);
  });

  it("reports a typo as a typo, not a wrong code", async () => {
    const code = await generateSharingRecoveryCode();
    const flipped = code.slice(0, 5) + (code[5] === "A" ? "B" : "A") + code.slice(6);
    await expect(parseSharingRecoveryCode(flipped)).rejects.toThrow(/typo/);
  });

  it("refuses anything that is not a generated code", async () => {
    await expect(parseSharingRecoveryCode("correct horse battery staple")).rejects.toMatchObject({
      code: "key",
    });
  });

  it("does not open another participant's recovery key", async () => {
    const { owner, viewer, enabled } = await sharedVault();
    const recovery = await recoveryKeyFor(viewer);
    const withRecovery = await write(owner, enabled, "v3", {
      participantKeys: { add: [recovery.addition] },
    });
    await expect(
      openSharingRecoveryKeyFromEnvelopeV1({
        code: await generateSharingRecoveryCode(),
        envelope: withRecovery,
      }),
    ).rejects.toThrow(/does not unlock any recovery key/);
  });
});
