import type { Authorization, AuthorizationProvider } from "../../core/types.js";
import { SyncKitError } from "../../core/errors.js";

export type CachedAuthorizationRecord = {
  profileId: string;
  accessToken: string;
  expiresAt: number;
  accountHint?: string;
};

/**
 * Opt-in persistence for short-lived Google access tokens used by Tier A
 * background polling. Not enabled by default; memory-only auth remains the
 * default policy.
 */
export class IndexedDbAuthorizationCache {
  constructor(
    private readonly options: {
      databaseName?: string;
      storeName?: string;
      indexedDB?: IDBFactory;
    } = {},
  ) {}

  async load(profileId: string): Promise<CachedAuthorizationRecord | null> {
    const stored: unknown = await this.transaction("readonly", (store) =>
      store.get(profileId),
    );
    if (!stored || typeof stored !== "object") return null;
    const record = stored as CachedAuthorizationRecord;
    if (
      typeof record.accessToken !== "string" ||
      typeof record.expiresAt !== "number"
    ) {
      return null;
    }
    return structuredClone(record);
  }

  async save(record: CachedAuthorizationRecord): Promise<void> {
    await this.transaction("readwrite", (store) =>
      store.put(structuredClone(record)),
    );
  }

  async delete(profileId: string): Promise<void> {
    await this.transaction("readwrite", (store) => store.delete(profileId));
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
          new SyncKitError("state", "IndexedDB authorization cache failed.", {
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
          "IndexedDB is required for authorization cache storage.",
        ),
      );
    }
    return new Promise((resolve, reject) => {
      const request = indexedDBImplementation.open(
        this.options.databaseName ?? "sync-kit-auth-cache",
        1,
      );
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(this.storeName())) {
          request.result.createObjectStore(this.storeName(), {
            keyPath: "profileId",
          });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(
          new SyncKitError(
            "state",
            "IndexedDB authorization cache could not be opened.",
            { cause: request.error },
          ),
        );
    });
  }

  private storeName(): string {
    return this.options.storeName ?? "google-authorization";
  }
}

export type CachingAuthorizationProviderOptions = {
  profileId: string;
  inner: AuthorizationProvider<Authorization>;
  cache: IndexedDbAuthorizationCache;
  accountHint?: string;
  expirySkewMs?: number;
  now?: () => number;
};

/**
 * Wraps an authorization provider and mirrors valid access tokens into the
 * opt-in IndexedDB cache for service-worker polling.
 */
export class CachingAuthorizationProvider
  implements AuthorizationProvider<Authorization>
{
  constructor(private readonly options: CachingAuthorizationProviderOptions) {}

  async authorize(): Promise<Authorization> {
    const authorization = await this.options.inner.authorize();
    const now = this.options.now?.() ?? Date.now();
    const skew = this.options.expirySkewMs ?? 60_000;
    const expiresAt =
      authorization.expiresAt ?? now + 3_600_000;
    if (expiresAt > now + skew) {
      await this.options.cache.save({
        profileId: this.options.profileId,
        accessToken: authorization.accessToken,
        expiresAt,
        ...(this.options.accountHint
          ? { accountHint: this.options.accountHint }
          : {}),
      });
    }
    return authorization;
  }

  async authorizeFromCache(): Promise<Authorization | null> {
    const record = await this.options.cache.load(this.options.profileId);
    if (!record) return null;
    const now = this.options.now?.() ?? Date.now();
    const skew = this.options.expirySkewMs ?? 60_000;
    if (record.expiresAt <= now + skew) {
      await this.options.cache.delete(this.options.profileId);
      return null;
    }
    return {
      accessToken: record.accessToken,
      expiresAt: record.expiresAt,
    };
  }

  clear(): void {
    this.options.inner.clear();
    void this.options.cache.delete(this.options.profileId);
  }
}
