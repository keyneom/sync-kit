import { describe, expect, it, vi } from "vitest";
import { bytesToBase64Url } from "../src/crypto/index.js";
import { GoogleDriveAppDataStore } from "../src/stores/google-drive/index.js";
import { DriveAppDataProtectedSharingIdentityStore } from "../src/sharing/appdata-identity-store.js";
import {
  PROTECTED_SHARING_IDENTITY_KIND,
  type ProtectedSharingIdentityV1,
} from "../src/sharing/web-passkey.js";

const authorization = { accessToken: "token" };

function validRecord(
  overrides: Partial<ProtectedSharingIdentityV1> = {},
): ProtectedSharingIdentityV1 {
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
    ...overrides,
  };
}

type DriveMock = GoogleDriveAppDataStore & {
  find: ReturnType<typeof vi.fn>;
  readText: ReturnType<typeof vi.fn>;
  write: ReturnType<typeof vi.fn>;
  delete: ReturnType<typeof vi.fn>;
};

function mockDrive(
  overrides: Partial<Record<keyof DriveMock, ReturnType<typeof vi.fn>>> = {},
): DriveMock {
  return {
    find: vi.fn(),
    readText: vi.fn(),
    write: vi.fn(),
    delete: vi.fn(),
    ...overrides,
  } as never;
}

describe("DriveAppDataProtectedSharingIdentityStore", () => {
  it("returns null when no identity blob exists", async () => {
    const drive = mockDrive({ find: vi.fn().mockResolvedValue(null) });
    const store = new DriveAppDataProtectedSharingIdentityStore({
      authorization: async () => authorization,
      drive,
    });
    expect(await store.load("easy-bc")).toBeNull();
    expect(drive.find).toHaveBeenCalledWith(
      "sync-kit-sharing-identity-easy-bc.json",
      authorization,
    );
    expect(drive.readText).not.toHaveBeenCalled();
  });

  it("reads and parses the app-data identity blob", async () => {
    const record = validRecord();
    const drive = mockDrive({
      find: vi.fn().mockResolvedValue({ fileId: "blob", name: "n" }),
      readText: vi.fn().mockResolvedValue(JSON.stringify(record)),
    });
    const store = new DriveAppDataProtectedSharingIdentityStore({
      authorization: async () => authorization,
      drive,
    });
    const loaded = await store.load("easy-bc");
    expect(loaded?.publicKey.keyId).toBe("key-id");
    expect(drive.readText).toHaveBeenCalledWith("blob", authorization);
  });

  it("creates a new blob when none exists", async () => {
    const drive = mockDrive({
      find: vi.fn().mockResolvedValue(null),
      write: vi.fn().mockResolvedValue("new-id"),
    });
    const store = new DriveAppDataProtectedSharingIdentityStore({
      authorization: async () => authorization,
      drive,
    });
    const record = validRecord();
    await store.save(record);
    expect(drive.write).toHaveBeenCalledWith(
      "sync-kit-sharing-identity-easy-bc.json",
      JSON.stringify(record),
      authorization,
      { contentType: "application/json" },
    );
  });

  it("overwrites the existing blob in place", async () => {
    const drive = mockDrive({
      find: vi.fn().mockResolvedValue({ fileId: "existing", name: "n" }),
      write: vi.fn().mockResolvedValue("existing"),
    });
    const store = new DriveAppDataProtectedSharingIdentityStore({
      authorization: async () => authorization,
      drive,
    });
    await store.save(validRecord());
    expect(drive.write).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      authorization,
      { existingId: "existing", contentType: "application/json" },
    );
  });

  it("deletes the blob when present and is a no-op otherwise", async () => {
    const present = mockDrive({
      find: vi.fn().mockResolvedValue({ fileId: "gone", name: "n" }),
    });
    const presentStore = new DriveAppDataProtectedSharingIdentityStore({
      authorization: async () => authorization,
      drive: present,
    });
    await presentStore.delete("easy-bc");
    expect(present.delete).toHaveBeenCalledWith("gone", authorization);

    const absent = mockDrive({ find: vi.fn().mockResolvedValue(null) });
    const absentStore = new DriveAppDataProtectedSharingIdentityStore({
      authorization: async () => authorization,
      drive: absent,
    });
    await absentStore.delete("easy-bc");
    expect(absent.delete).not.toHaveBeenCalled();
  });

  it("honors a custom filename derivation", async () => {
    const drive = mockDrive({ find: vi.fn().mockResolvedValue(null) });
    const store = new DriveAppDataProtectedSharingIdentityStore({
      authorization: async () => authorization,
      filename: (appId) => `custom/${appId}.json`,
      drive,
    });
    await store.load("easy-bc");
    expect(drive.find).toHaveBeenCalledWith("custom/easy-bc.json", authorization);
  });
});
