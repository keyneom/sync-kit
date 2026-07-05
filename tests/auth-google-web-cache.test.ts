import { describe, expect, it, vi } from "vitest";
import {
  CachingAuthorizationProvider,
  IndexedDbAuthorizationCache,
} from "../src/auth/google-web/cache.js";
import type { AuthorizationProvider } from "../src/core/types.js";

describe("IndexedDbAuthorizationCache", () => {
  it("persists and clears cached authorization records", async () => {
    const indexedDB = createFakeIndexedDB();
    const cache = new IndexedDbAuthorizationCache({
      indexedDB,
      databaseName: "test-auth-cache",
    });

    await cache.save({
      profileId: "profile-1",
      accessToken: "token-1",
      expiresAt: Date.parse("2026-07-01T13:00:00.000Z"),
      accountHint: "user@example.com",
    });
    await expect(cache.load("profile-1")).resolves.toEqual({
      profileId: "profile-1",
      accessToken: "token-1",
      expiresAt: Date.parse("2026-07-01T13:00:00.000Z"),
      accountHint: "user@example.com",
    });
    await cache.delete("profile-1");
    await expect(cache.load("profile-1")).resolves.toBeNull();
  });
});

describe("CachingAuthorizationProvider", () => {
  it("mirrors valid tokens into the cache and reads them back", async () => {
    const indexedDB = createFakeIndexedDB();
    const cache = new IndexedDbAuthorizationCache({
      indexedDB,
      databaseName: "test-auth-cache",
    });
    const clear = vi.fn();
    const inner: AuthorizationProvider<{ accessToken: string; expiresAt?: number }> =
      {
        authorize: vi.fn(async () => ({
          accessToken: "fresh-token",
          expiresAt: Date.parse("2026-07-01T13:00:00.000Z"),
        })),
        clear,
      };
    const provider = new CachingAuthorizationProvider({
      profileId: "profile-1",
      inner,
      cache,
      now: () => Date.parse("2026-07-01T12:00:00.000Z"),
    });

    await expect(provider.authorize()).resolves.toEqual({
      accessToken: "fresh-token",
      expiresAt: Date.parse("2026-07-01T13:00:00.000Z"),
    });
    await expect(provider.authorizeFromCache()).resolves.toEqual({
      accessToken: "fresh-token",
      expiresAt: Date.parse("2026-07-01T13:00:00.000Z"),
    });
    provider.clear();
    expect(clear).toHaveBeenCalled();
    await expect(provider.authorizeFromCache()).resolves.toBeNull();
  });
});

function createFakeIndexedDB(): IDBFactory {
  const databases = new Map<string, Map<string, unknown>>();

  return {
    open(name: string) {
      if (!databases.has(name)) databases.set(name, new Map());
      const store = databases.get(name);
      if (!store) throw new Error("Missing fake database store.");
      const request = {
        result: undefined as IDBDatabase | undefined,
        onsuccess: null as (() => void) | null,
        onerror: null as (() => void) | null,
        onupgradeneeded: null as ((event: IDBVersionChangeEvent) => void) | null,
        error: null,
      };

      queueMicrotask(() => {
        const db = {
          objectStoreNames: {
            contains: (storeName: string) =>
              storeName === "google-authorization",
          },
          createObjectStore: () => ({ keyPath: "profileId" }),
          transaction: () => {
            const transaction = {
              oncomplete: null as (() => void) | null,
              onabort: null as (() => void) | null,
              objectStore: () => ({
                get: (key: string) => {
                  const getRequest = {
                    result: store.get(key),
                    onsuccess: null as (() => void) | null,
                    onerror: null as (() => void) | null,
                  };
                  queueMicrotask(() => getRequest.onsuccess?.());
                  return getRequest as IDBRequest;
                },
                put: (value: { profileId: string }) => {
                  store.set(value.profileId, structuredClone(value));
                  const putRequest = {
                    onsuccess: null as (() => void) | null,
                    onerror: null as (() => void) | null,
                  };
                  queueMicrotask(() => putRequest.onsuccess?.());
                  return putRequest as IDBRequest;
                },
                delete: (key: string) => {
                  store.delete(key);
                  const deleteRequest = {
                    onsuccess: null as (() => void) | null,
                    onerror: null as (() => void) | null,
                  };
                  queueMicrotask(() => deleteRequest.onsuccess?.());
                  return deleteRequest as IDBRequest;
                },
              }),
            };
            queueMicrotask(() => transaction.oncomplete?.());
            return transaction as unknown as IDBTransaction;
          },
          close: () => undefined,
        };
        request.result = db as unknown as IDBDatabase;
        request.onupgradeneeded?.({} as IDBVersionChangeEvent);
        request.onsuccess?.();
      });

      return request as IDBOpenDBRequest;
    },
  } as IDBFactory;
}
