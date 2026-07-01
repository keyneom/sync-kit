import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalJson,
  createWebCryptoBackend,
  decryptSyncEnvelopeV1,
  defineV1CompatibilityProfile,
  deriveContentKey,
  encryptSyncEnvelopeV1,
  parseSyncEnvelopeV1,
  type SyncEnvelopeV1,
  type V1KeyMetadata,
} from "../src/crypto/index.js";
import { SyncKitError, type SyncCodec } from "../src/core/index.js";
import {
  easyBcTestProfile,
  familyChoresTestProfile,
} from "./compatibility-profiles.js";

type Fixture = {
  secret: string;
  payload: unknown;
  envelope: SyncEnvelopeV1;
};

const codec: SyncCodec<unknown> = {
  serialize: (value) => value,
  parse: (value) => value,
  merge: (local) => local,
  fingerprint: JSON.stringify,
  updatedAt: (value) =>
    (value as { exportedAt?: string }).exportedAt ??
    "2026-06-29T00:00:00.000Z",
};
const backend = createWebCryptoBackend();

describe("v1 compatibility crypto", () => {
  it("decrypts both EasyBC vectors consumed by web and Android", async () => {
    for (const filename of [
      "easybc-web-uncompressed.json",
      "easybc-web-android-gzip.json",
    ]) {
      const fixture = await loadFixture(filename);
      const key = await deriveContentKey(
        easyBcTestProfile,
        base64UrlToBytes(fixture.secret),
        base64UrlToBytes(fixture.envelope.kdfSalt),
        backend,
      );
      await expect(
        decryptSyncEnvelopeV1(
          fixture.envelope,
          key,
          easyBcTestProfile,
          codec,
          backend,
        ),
      ).resolves.toEqual(fixture.payload);
    }
  });

  it("reproduces the uncompressed EasyBC WebCrypto ciphertext", async () => {
    const fixture = await loadFixture("easybc-web-uncompressed.json");
    const metadata = metadataFrom(fixture.envelope);
    const key = await deriveContentKey(
      easyBcTestProfile,
      base64UrlToBytes(fixture.secret),
      metadata.kdfSalt,
      backend,
    );
    const encrypted = await encryptSyncEnvelopeV1(
      fixture.payload,
      key,
      metadata,
      { ...easyBcTestProfile, compression: "none" },
      codec,
      backend,
      { nonce: base64UrlToBytes(fixture.envelope.nonce) },
    );

    expect(encrypted).toEqual(fixture.envelope);
  });

  it("reproduces and decrypts the Family Chores v1 vector", async () => {
    const fixture = await loadFixture("family-chores-web-uncompressed.json");
    const metadata = metadataFrom(fixture.envelope);
    const key = await deriveContentKey(
      familyChoresTestProfile,
      base64UrlToBytes(fixture.secret),
      metadata.kdfSalt,
      backend,
    );
    const encrypted = await encryptSyncEnvelopeV1(
      fixture.payload,
      key,
      metadata,
      familyChoresTestProfile,
      codec,
      backend,
      { nonce: base64UrlToBytes(fixture.envelope.nonce) },
    );

    expect(encrypted).toEqual(fixture.envelope);
    await expect(
      decryptSyncEnvelopeV1(
        encrypted,
        key,
        familyChoresTestProfile,
        codec,
        backend,
      ),
    ).resolves.toEqual(fixture.payload);
  });

  it("uses gzip only when it reduces the EasyBC payload", async () => {
    const fixture = await loadFixture("easybc-web-uncompressed.json");
    const metadata = metadataFrom(fixture.envelope);
    const key = await deriveContentKey(
      easyBcTestProfile,
      base64UrlToBytes(fixture.secret),
      metadata.kdfSalt,
      backend,
    );
    const payload = {
      exportedAt: "2026-06-29T00:00:00.000Z",
      notes: "repeatable synthetic fixture text ".repeat(300),
    };
    const encrypted = await encryptSyncEnvelopeV1(
      payload,
      key,
      metadata,
      easyBcTestProfile,
      codec,
      backend,
    );

    expect(encrypted.compression).toBe("gzip");
    await expect(
      decryptSyncEnvelopeV1(
        encrypted,
        key,
        easyBcTestProfile,
        codec,
        backend,
      ),
    ).resolves.toEqual(payload);
  });

  it("rejects tampering, wrong secrets, wrong contexts, and malformed envelopes", async () => {
    const fixture = await loadFixture("easybc-web-uncompressed.json");
    const failures = await loadJson<{
      wrongSecret: string;
      tamperedEnvelope: SyncEnvelopeV1;
      wrongContextEnvelope: SyncEnvelopeV1;
      malformedEnvelope: unknown;
    }>("failures.json");
    const correctKey = await deriveContentKey(
      easyBcTestProfile,
      base64UrlToBytes(fixture.secret),
      base64UrlToBytes(fixture.envelope.kdfSalt),
      backend,
    );
    const wrongKey = await deriveContentKey(
      easyBcTestProfile,
      base64UrlToBytes(failures.wrongSecret),
      base64UrlToBytes(fixture.envelope.kdfSalt),
      backend,
    );

    await expect(
      decryptSyncEnvelopeV1(
        failures.tamperedEnvelope,
        correctKey,
        easyBcTestProfile,
        codec,
        backend,
      ),
    ).rejects.toMatchObject({ code: "crypto" });
    await expect(
      decryptSyncEnvelopeV1(
        fixture.envelope,
        wrongKey,
        easyBcTestProfile,
        codec,
        backend,
      ),
    ).rejects.toMatchObject({ code: "crypto" });
    await expect(
      decryptSyncEnvelopeV1(
        failures.wrongContextEnvelope,
        correctKey,
        easyBcTestProfile,
        codec,
        backend,
      ),
    ).rejects.toMatchObject({ code: "crypto" });
    expect(() =>
      parseSyncEnvelopeV1(failures.malformedEnvelope, easyBcTestProfile),
    ).toThrow(SyncKitError);
  });

  it("distinguishes authenticated invalid gzip data from key failure", async () => {
    const fixture = await loadFixture("easybc-web-uncompressed.json");
    const failures = await loadJson<{
      decompressionErrorEnvelope: SyncEnvelopeV1;
    }>("failures.json");
    const key = await deriveContentKey(
      easyBcTestProfile,
      base64UrlToBytes(fixture.secret),
      base64UrlToBytes(failures.decompressionErrorEnvelope.kdfSalt),
      backend,
    );
    await expect(
      decryptSyncEnvelopeV1(
        failures.decompressionErrorEnvelope,
        key,
        easyBcTestProfile,
        codec,
        backend,
      ),
    ).rejects.toMatchObject({ code: "decompression" });
  });
});

describe("portable encodings", () => {
  it("round-trips unpadded base64url and rejects malformed input", () => {
    const bytes = Uint8Array.of(0, 1, 2, 250, 251, 252, 253, 254, 255);
    expect(base64UrlToBytes(bytesToBase64Url(bytes))).toEqual(bytes);
    expect(() => base64UrlToBytes("%%%")).toThrow(/base64url/u);
  });

  it("canonicalizes object keys recursively", () => {
    expect(canonicalJson({ z: 1, a: { y: 2, b: 3 } })).toBe(
      '{"a":{"b":3,"y":2},"z":1}',
    );
  });
});

describe("consumer-owned profiles", () => {
  it("fixes protocol constants without bundling an application preset", () => {
    const profile = defineV1CompatibilityProfile({
      appId: "fixture-app",
      filename: "fixture-sync-v1.json",
      aad: "fixture-envelope-v1",
      hkdfInfo: "fixture-content-key-v1",
      compression: "none",
      passkey: {
        rpName: "Fixture",
        userName: "encrypted-sync",
        userDisplayName: "Fixture encrypted sync",
        algorithm: -7,
        residentKey: "required",
        userVerification: "required",
        timeoutMs: 60_000,
      },
    });

    expect(profile).toMatchObject({
      appId: "fixture-app",
      algorithm: "AES-256-GCM+HKDF-SHA-256",
      readVersions: [1],
      writeVersion: 1,
      nonceBytes: 12,
      tagBits: 128,
    });
  });

  it("rejects incomplete consumer configuration", () => {
    expect(() =>
      defineV1CompatibilityProfile({
        ...easyBcTestProfile,
        appId: "",
      }),
    ).toThrow(/appId/u);
  });
});

function metadataFrom(envelope: SyncEnvelopeV1): V1KeyMetadata {
  return {
    credentialId: envelope.credentialId,
    rpId: envelope.rpId,
    prfInput: base64UrlToBytes(envelope.prfInput),
    kdfSalt: base64UrlToBytes(envelope.kdfSalt),
  };
}

async function loadFixture(filename: string): Promise<Fixture> {
  return loadJson<Fixture>(filename);
}

async function loadJson<T>(filename: string): Promise<T> {
  return JSON.parse(
    await readFile(
      new URL(`../fixtures/v1/${filename}`, import.meta.url),
      "utf8",
    ),
  ) as T;
}
