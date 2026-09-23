import { describe, expect, it } from "vitest";
import type { SyncCodec } from "../src/core/types.js";
import {
  createV1EnvelopeCrypto,
  createWebCryptoBackend,
  defineV1CompatibilityProfile,
  deriveContentKey,
  generateRecoveryCode,
  type SyncEnvelopeV1,
  type V1KeyMetadata,
} from "../src/crypto/index.js";
import { createSnapshotSync } from "../src/snapshot/index.js";

type Value = { items: string[]; updatedAt: string };

const backend = createWebCryptoBackend();
const codec: SyncCodec<Value> = {
  serialize: (value) => value,
  parse: (value) => value as Value,
  merge: (local, remote) => ({
    items: [...new Set([...remote.items, ...local.items])].sort(),
    updatedAt: local.updatedAt > remote.updatedAt ? local.updatedAt : remote.updatedAt,
  }),
  fingerprint: (value) => JSON.stringify([...value.items].sort()),
  updatedAt: (value) => value.updatedAt,
};

function profile(versions: { readVersions?: readonly (1 | 2)[]; writeVersion?: 1 | 2 } = {}) {
  return defineV1CompatibilityProfile({
    appId: "recovery-app",
    filename: "recovery-app.json",
    aad: "recovery-app-v1",
    hkdfInfo: "recovery-app content key",
    compression: "gzip-if-smaller",
    passkey: {
      rpName: "Recovery App",
      userName: "user",
      userDisplayName: "User",
      algorithm: -7,
      residentKey: "required",
      userVerification: "required",
      timeoutMs: 60_000,
    },
    ...versions,
  });
}

const V2 = { readVersions: [1, 2] as const };

/**
 * A stand-in for a passkey provider: each credential's PRF secret lives in
 * `authenticator`, and keys derive from it exactly as the real providers do.
 * Deleting a credential simulates losing the passkey.
 */
function passkeys(appProfile: ReturnType<typeof profile>) {
  const authenticator = new Map<string, Uint8Array>();
  let created = 0;
  return {
    authenticator,
    provider: {
      async create() {
        const credentialId = `credential-${++created}`;
        const secret = backend.randomBytes(32);
        authenticator.set(credentialId, secret);
        const metadata: V1KeyMetadata = {
          credentialId,
          rpId: "recovery.example",
          prfInput: backend.randomBytes(32),
          kdfSalt: backend.randomBytes(32),
        };
        return { metadata, key: await deriveContentKey(appProfile, secret, metadata.kdfSalt, backend) };
      },
      async unlock(envelope: SyncEnvelopeV1) {
        const secret = authenticator.get(envelope.credentialId);
        if (!secret) throw new Error("This passkey is not available on this device.");
        return deriveContentKey(
          appProfile,
          secret,
          Uint8Array.from(Buffer.from(envelope.kdfSalt, "base64url")),
          backend,
        );
      },
      clear: () => undefined,
    },
  };
}

function device(
  appProfile: ReturnType<typeof profile>,
  cloud: { envelope: SyncEnvelopeV1 | null },
  keys: ReturnType<typeof passkeys>,
  local: Value,
) {
  const state = { local };
  const envelopeCrypto = createV1EnvelopeCrypto(appProfile, codec, backend);
  const controller = createSnapshotSync({
    appId: appProfile.appId,
    codec,
    envelopeCrypto,
    keyProvider: keys.provider,
    authorizationProvider: { authorize: async () => ({ accessToken: "token" }), clear: () => undefined },
    cloudStore: {
      find: async () => (cloud.envelope ? { fileId: "file", envelope: cloud.envelope } : null),
      write: async (_appId, envelope) => {
        cloud.envelope = envelope;
        return "file";
      },
    },
    readLocal: () => state.local,
    applyMerged: (value) => {
      state.local = value;
    },
    envelopeUpdatedAt: (envelope) => envelope.updatedAt,
  });
  return { controller, envelopeCrypto, state };
}

/** The snapshot in the cloud, failing loudly if there is none. */
function stored(cloud: { envelope: SyncEnvelopeV1 | null }): SyncEnvelopeV1 {
  if (!cloud.envelope) throw new Error("No snapshot has been written.");
  return cloud.envelope;
}

const at = (minute: number) => `2026-09-23T00:${String(minute).padStart(2, "0")}:00.000Z`;

describe("snapshot v2 and recovery codes", () => {
  it("leaves v1 exactly as it was unless a profile opts in", async () => {
    const appProfile = profile();
    const cloud = { envelope: null as SyncEnvelopeV1 | null };
    const phone = device(appProfile, cloud, passkeys(appProfile), { items: ["a"], updatedAt: at(1) });
    await phone.controller.setup();
    expect(cloud.envelope).toMatchObject({ schemaVersion: 1 });
    expect(Object.keys(stored(cloud)).sort()).toEqual(
      ["algorithm", "ciphertext", "credentialId", "kdfSalt", "nonce", "prfInput", "rpId", "schemaVersion", "updatedAt"]
        .concat(stored(cloud).compression ? ["compression"] : [])
        .sort(),
    );
    await expect(phone.controller.setRecoveryCode(await generateRecoveryCode(backend))).rejects.toMatchObject({
      code: "configuration",
    });
  });

  it("refuses a v2 snapshot on a device whose profile does not read v2", async () => {
    const v2Profile = profile({ ...V2, writeVersion: 2 });
    const cloud = { envelope: null as SyncEnvelopeV1 | null };
    const keys = passkeys(v2Profile);
    await device(v2Profile, cloud, keys, { items: ["a"], updatedAt: at(1) }).controller.setup();
    expect(cloud.envelope?.schemaVersion).toBe(2);
    const old = device(profile(), cloud, keys, { items: [], updatedAt: at(0) });
    await expect(old.controller.sync("foreground")).rejects.toThrow(/readVersions/);
  });

  it("recovers a lost passkey on a new device with the code alone", async () => {
    const appProfile = profile(V2);
    const cloud = { envelope: null as SyncEnvelopeV1 | null };
    const keys = passkeys(appProfile);
    const phone = device(appProfile, cloud, keys, { items: ["a"], updatedAt: at(1) });
    await phone.controller.setup();
    const code = await generateRecoveryCode(backend);
    await phone.controller.setRecoveryCode(code);
    expect(cloud.envelope).toMatchObject({ schemaVersion: 2, appId: "recovery-app" });
    expect(cloud.envelope?.recoveryKey).toBeDefined();

    // Ordinary sync keeps the version and the recovery lock untouched.
    phone.state.local = { items: ["a", "b"], updatedAt: at(2) };
    const lockBefore = cloud.envelope?.recoveryKey;
    await phone.controller.sync("change");
    expect(cloud.envelope?.schemaVersion).toBe(2);
    expect(cloud.envelope?.recoveryKey).toEqual(lockBefore);

    // The passkey is gone. A new device has only the code.
    keys.authenticator.clear();
    const newDevice = device(appProfile, cloud, keys, { items: ["c"], updatedAt: at(3) });
    await expect(newDevice.controller.sync("foreground")).rejects.toThrow(/not available/);
    await expect(newDevice.controller.recover(code)).resolves.toMatchObject({
      operation: "recover",
      outcome: "recovered",
      value: { items: ["a", "b", "c"] },
    });
    // Locked under the new passkey from here on, and the code still works.
    await expect(newDevice.controller.sync("foreground")).resolves.toMatchObject({ outcome: "unchanged" });
    await expect(newDevice.envelopeCrypto.decryptWithRecoveryCode(stored(cloud), code)).resolves.toMatchObject({
      items: ["a", "b", "c"],
    });
  });

  it("distinguishes a typo from a wrong code, and removes the code on request", async () => {
    const appProfile = profile(V2);
    const cloud = { envelope: null as SyncEnvelopeV1 | null };
    const phone = device(appProfile, cloud, passkeys(appProfile), { items: ["a"], updatedAt: at(1) });
    await phone.controller.setup();
    const code = await generateRecoveryCode(backend);
    await phone.controller.setRecoveryCode(code);
    const typo = code.slice(0, 5) + (code[5] === "A" ? "B" : "A") + code.slice(6);
    await expect(phone.envelopeCrypto.decryptWithRecoveryCode(stored(cloud), typo)).rejects.toThrow(/typo/);
    await expect(
      phone.envelopeCrypto.decryptWithRecoveryCode(stored(cloud), await generateRecoveryCode(backend)),
    ).rejects.toThrow(/does not unlock/);
    await phone.controller.setRecoveryCode(null);
    expect(cloud.envelope?.recoveryKey).toBeUndefined();
    await expect(phone.envelopeCrypto.decryptWithRecoveryCode(stored(cloud), code)).rejects.toThrow(
      /no recovery code/,
    );
  });

  it("migrates explicitly and reversibly, and moving to v1 drops the code", async () => {
    const appProfile = profile(V2);
    const cloud = { envelope: null as SyncEnvelopeV1 | null };
    const keys = passkeys(appProfile);
    const phone = device(appProfile, cloud, keys, { items: ["a"], updatedAt: at(1) });
    await phone.controller.setup();
    await phone.controller.setRecoveryCode(await generateRecoveryCode(backend));
    await phone.controller.migrateVersion(1);
    expect(cloud.envelope).toMatchObject({ schemaVersion: 1 });
    expect(cloud.envelope?.recoveryKey).toBeUndefined();
    // A device that only reads v1 opens it again.
    const old = device(profile(), cloud, keys, { items: [], updatedAt: at(0) });
    await expect(old.controller.sync("foreground")).resolves.toMatchObject({ value: { items: ["a"] } });
    await phone.controller.migrateVersion(2);
    expect(cloud.envelope?.schemaVersion).toBe(2);
  });

  it("authenticates the whole v2 header and its appId", async () => {
    const appProfile = profile({ ...V2, writeVersion: 2 });
    const cloud = { envelope: null as SyncEnvelopeV1 | null };
    const keys = passkeys(appProfile);
    const phone = device(appProfile, cloud, keys, { items: ["a"], updatedAt: at(1) });
    await phone.controller.setup();
    const envelope = stored(cloud);
    const key = await keys.provider.unlock(envelope);
    await expect(phone.envelopeCrypto.decrypt({ ...envelope, updatedAt: at(9) }, key)).rejects.toMatchObject({
      code: "crypto",
    });
    const other = createV1EnvelopeCrypto({ ...appProfile, appId: "another-app" }, codec, backend);
    await expect(other.decrypt(envelope, key)).rejects.toThrow(/belongs to recovery-app/);
  });

  it("validates versions in the profile", () => {
    expect(() => profile({ readVersions: [2] })).toThrow(/must include 1/);
    expect(() => profile({ writeVersion: 2 })).toThrow(/one of readVersions/);
  });
});
