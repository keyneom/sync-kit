import { describe, expect, it } from "vitest";
import { IndexedDbSharedBackupRegistry } from "../src/sharing/registry-indexeddb.js";

describe("IndexedDbSharedBackupRegistry", () => {
  it("persists dataset registry records by datasetId", async () => {
    const indexedDB = createFakeIndexedDB();
    const registry = new IndexedDbSharedBackupRegistry({
      indexedDB,
      databaseName: "test-shared-backups",
      storeName: "registry",
    });

    await registry.set({
      datasetId: "tasks",
      trustedOwnerKeyId: "owner-key",
      fileId: "file-1",
      lastRevisionId: "rev-1",
    });
    await expect(registry.get("tasks")).resolves.toEqual({
      datasetId: "tasks",
      trustedOwnerKeyId: "owner-key",
      fileId: "file-1",
      lastRevisionId: "rev-1",
    });
    await registry.delete("tasks");
    await expect(registry.get("tasks")).resolves.toBeNull();
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
            contains: (storeName: string) => storeName === "registry",
          },
          createObjectStore: () => ({ keyPath: "datasetId" }),
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
                put: (value: { datasetId: string }) => {
                  store.set(value.datasetId, structuredClone(value));
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
        } as unknown as IDBDatabase;
        request.result = db;
        request.onupgradeneeded?.({
          target: request,
        } as unknown as IDBVersionChangeEvent);
        request.onsuccess?.();
      });

      return request as IDBOpenDBRequest;
    },
    deleteDatabase: () => ({}) as IDBOpenDBRequest,
    cmp: () => 0,
    databases: () => Promise.resolve([]),
  };
}
