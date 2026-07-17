import { describe, expect, it, vi } from "vitest";
import type { WebPasskeyProvider } from "../src/keys/web-passkey/index.js";
import {
  PasskeyProtectedSharingIdentityProvider,
  type ProtectedSharingIdentityStore,
  type ProtectedSharingIdentityV1,
} from "../src/sharing/web-passkey.js";

describe("PasskeyProtectedSharingIdentityProvider", () => {
  it("returns exactly one winner when two contexts create concurrently", async () => {
    let stored: ProtectedSharingIdentityV1 | null = null;
    let arrivals = 0;
    let release!: () => void;
    const bothArrived = new Promise<void>((resolve) => {
      release = resolve;
    });
    const store: ProtectedSharingIdentityStore = {
      load: async () => stored,
      save: async (record) => {
        stored = record;
      },
      saveIfAbsent: async (record) => {
        arrivals += 1;
        if (arrivals === 2) release();
        await bothArrived;
        if (stored) return false;
        stored = record;
        return true;
      },
      delete: async () => {
        stored = null;
      },
    };
    const first = provider(store, 1);
    const second = provider(store, 2);

    const results = await Promise.allSettled([
      first.getOrCreate(),
      second.getOrCreate(),
    ]);
    const fulfilled = results.filter(
      (result): result is PromiseFulfilledResult<Awaited<ReturnType<typeof first.getOrCreate>>> =>
        result.status === "fulfilled",
    );
    const rejected = results.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.reason).toMatchObject({ code: "conflict" });
    const persisted = stored as ProtectedSharingIdentityV1 | null;
    expect(persisted?.publicKey.keyId).toBe(
      fulfilled[0]?.value.publicKey.keyId,
    );
  });

  it("serializes create across browser contexts before passkey creation", async () => {
    let stored: ProtectedSharingIdentityV1 | null = null;
    const store: ProtectedSharingIdentityStore = {
      load: async () => stored,
      save: async (record) => {
        stored = record;
      },
      delete: async () => {
        stored = null;
      },
    };
    const locks = serialLockManager();
    const firstPasskey = passkeyProvider(1);
    const secondPasskey = passkeyProvider(2);
    const first = new PasskeyProtectedSharingIdentityProvider({
      appId: "fixture-app",
      passkeyProvider: firstPasskey,
      store,
      locks,
    });
    const second = new PasskeyProtectedSharingIdentityProvider({
      appId: "fixture-app",
      passkeyProvider: secondPasskey,
      store,
      locks,
    });

    const results = await Promise.allSettled([first.create(), second.create()]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(firstPasskey.create).toHaveBeenCalledTimes(1);
    expect(secondPasskey.create).not.toHaveBeenCalled();
  });
});

function provider(
  store: ProtectedSharingIdentityStore,
  marker: number,
): PasskeyProtectedSharingIdentityProvider {
  return new PasskeyProtectedSharingIdentityProvider({
    appId: "fixture-app",
    passkeyProvider: passkeyProvider(marker),
    store,
    locks: null,
  });
}

function passkeyProvider(marker: number): WebPasskeyProvider<CryptoKey> & {
  create: ReturnType<typeof vi.fn>;
} {
  const wrappingKey = crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return {
    create: vi.fn(async () => ({
      metadata: {
        credentialId: marker === 1 ? "AQ" : "Ag",
        rpId: "example.test",
        prfInput: new Uint8Array(32).fill(marker),
        kdfSalt: new Uint8Array(32).fill(marker + 2),
      },
      key: await wrappingKey,
    })),
    clear: vi.fn(),
  } as unknown as WebPasskeyProvider<CryptoKey> & {
    create: ReturnType<typeof vi.fn>;
  };
}

function serialLockManager(): LockManager {
  let tail: Promise<void> = Promise.resolve();
  return {
    request: <T>(
      _name: string,
      callback: () => Promise<T>,
    ): Promise<T> => {
      const result = tail.then(callback);
      tail = result.then(
        () => undefined,
        () => undefined,
      );
      return result;
    },
  } as LockManager;
}
