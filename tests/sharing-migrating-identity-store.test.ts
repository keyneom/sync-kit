import { describe, expect, it, vi } from "vitest";
import { bytesToBase64Url } from "../src/crypto/index.js";
import { MigratingProtectedSharingIdentityStore } from "../src/sharing/migrating-identity-store.js";
import {
  PROTECTED_SHARING_IDENTITY_KIND,
  type ProtectedSharingIdentityStore,
  type ProtectedSharingIdentityV1,
} from "../src/sharing/web-passkey.js";

function validRecord(): ProtectedSharingIdentityV1 {
  return {
    schemaVersion: 1,
    kind: PROTECTED_SHARING_IDENTITY_KIND,
    appId: "easy-bc",
    rpId: "example.com",
    credentialId: bytesToBase64Url(new Uint8Array([1, 2, 3, 4])),
    prfInput: bytesToBase64Url(new Uint8Array(32)),
    kdfSalt: bytesToBase64Url(new Uint8Array(32)),
    nonce: bytesToBase64Url(new Uint8Array(12)),
    publicKey: {
      keyId: "key-id",
      encryptionPublicKey: "enc",
      signingPublicKey: "sig",
    } as ProtectedSharingIdentityV1["publicKey"],
    encryptedPrivateKeys: bytesToBase64Url(new Uint8Array([9, 8, 7])),
  };
}

function stubStore(
  overrides: Partial<ProtectedSharingIdentityStore> = {},
): ProtectedSharingIdentityStore & {
  load: ReturnType<typeof vi.fn>;
  save: ReturnType<typeof vi.fn>;
  delete: ReturnType<typeof vi.fn>;
} {
  return {
    load: vi.fn().mockResolvedValue(null),
    save: vi.fn().mockResolvedValue(undefined),
    delete: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  } as never;
}

describe("MigratingProtectedSharingIdentityStore", () => {
  it("returns the primary record without touching legacy", async () => {
    const record = validRecord();
    const primary = stubStore({ load: vi.fn().mockResolvedValue(record) });
    const legacy = stubStore();
    const store = new MigratingProtectedSharingIdentityStore({ primary, legacy });
    expect((await store.load("easy-bc"))?.publicKey.keyId).toBe("key-id");
    expect(legacy.load).not.toHaveBeenCalled();
    expect(primary.save).not.toHaveBeenCalled();
  });

  it("promotes the legacy record to primary when primary is empty", async () => {
    const record = validRecord();
    const primary = stubStore();
    const legacy = stubStore({
      load: vi.fn().mockResolvedValue(JSON.stringify(record)),
    });
    const store = new MigratingProtectedSharingIdentityStore({ primary, legacy });
    const loaded = await store.load("easy-bc");
    expect(loaded?.publicKey.keyId).toBe("key-id");
    expect(primary.save).toHaveBeenCalledOnce();
  });

  it("still returns the legacy record when promotion fails", async () => {
    const record = validRecord();
    const primary = stubStore({
      save: vi.fn().mockRejectedValue(new Error("offline")),
    });
    const legacy = stubStore({ load: vi.fn().mockResolvedValue(record) });
    const store = new MigratingProtectedSharingIdentityStore({ primary, legacy });
    expect((await store.load("easy-bc"))?.publicKey.keyId).toBe("key-id");
  });

  it("returns null when neither store has an identity", async () => {
    const store = new MigratingProtectedSharingIdentityStore({
      primary: stubStore(),
      legacy: stubStore(),
    });
    expect(await store.load("easy-bc")).toBeNull();
  });

  it("writes only to primary and deletes from both", async () => {
    const primary = stubStore();
    const legacy = stubStore();
    const store = new MigratingProtectedSharingIdentityStore({ primary, legacy });
    const record = validRecord();
    await store.save(record);
    expect(primary.save).toHaveBeenCalledWith(record);
    expect(legacy.save).not.toHaveBeenCalled();
    await store.delete("easy-bc");
    expect(primary.delete).toHaveBeenCalledWith("easy-bc");
    expect(legacy.delete).toHaveBeenCalledWith("easy-bc");
  });
});
