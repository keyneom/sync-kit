import { SyncKitError } from "../core/errors.js";
import type {
  SharedBackupRegistry,
  SharedDatasetRegistryRecord,
} from "./controller.js";

/**
 * Optional browser persistence for the protocol dataset registry. Application
 * profile metadata such as display names and switcher labels remain outside
 * sync-kit.
 */
export class IndexedDbSharedBackupRegistry implements SharedBackupRegistry {
  constructor(
    private readonly options: {
      databaseName?: string;
      storeName?: string;
      indexedDB?: IDBFactory;
    } = {},
  ) {}

  async get(datasetId: string): Promise<SharedDatasetRegistryRecord | null> {
    const stored: unknown = await this.transaction("readonly", (store) =>
      store.get(datasetId),
    );
    if (!stored || typeof stored !== "object") return null;
    return structuredClone(stored as SharedDatasetRegistryRecord);
  }

  async set(record: SharedDatasetRegistryRecord): Promise<void> {
    await this.transaction("readwrite", (store) =>
      store.put(structuredClone(record)),
    );
  }

  async delete(datasetId: string): Promise<void> {
    await this.transaction("readwrite", (store) => store.delete(datasetId));
  }

  private async transaction<T>(
    mode: IDBTransactionMode,
    operation: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    const database = await this.open();
    return new Promise<T>((resolve, reject) => {
      const transaction = database.transaction(this.storeName(), mode);
      const request = operation(transaction.objectStore(this.storeName()));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(
          new SyncKitError("state", "IndexedDB shared-backup registry failed.", {
            cause: request.error,
          }),
        );
      transaction.oncomplete = () => database.close();
      transaction.onabort = () => database.close();
    });
  }

  private open(): Promise<IDBDatabase> {
    const indexedDBImplementation =
      this.options.indexedDB ??
      (typeof indexedDB === "undefined" ? undefined : indexedDB);
    if (!indexedDBImplementation) {
      return Promise.reject(
        new SyncKitError(
          "configuration",
          "IndexedDB is required for shared-backup registry storage.",
        ),
      );
    }
    return new Promise((resolve, reject) => {
      const request = indexedDBImplementation.open(
        this.options.databaseName ?? "sync-kit-shared-backups",
        1,
      );
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(this.storeName())) {
          request.result.createObjectStore(this.storeName(), {
            keyPath: "datasetId",
          });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(
          new SyncKitError(
            "state",
            "IndexedDB shared-backup registry could not be opened.",
            { cause: request.error },
          ),
        );
    });
  }

  private storeName(): string {
    return this.options.storeName ?? "registry";
  }
}
