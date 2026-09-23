import { SyncKitError, asSyncKitError } from "../core/errors.js";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalAad,
} from "../crypto/index.js";
import { copyBuffer } from "../crypto/runtime.js";
import {
  WebPasskeyProvider,
  type WebPasskeyKeyMetadata,
} from "../keys/web-passkey/index.js";
import type { SharingPublicKeyV1 } from "./index.js";
import {
  generateSharingIdentityMaterial,
  importSharingIdentity,
} from "./identity-material.js";
import type { WebCryptoSharingIdentity } from "./web-crypto.js";

export const PROTECTED_SHARING_IDENTITY_KIND =
  "sync-kit-protected-sharing-identity" as const;

export type ProtectedSharingIdentityV1 = {
  schemaVersion: 1;
  kind: typeof PROTECTED_SHARING_IDENTITY_KIND;
  appId: string;
  rpId: string;
  credentialId: string;
  credentialPublicKey?: JsonWebKey;
  prfInput: string;
  kdfSalt: string;
  nonce: string;
  publicKey: SharingPublicKeyV1;
  encryptedPrivateKeys: string;
};

export interface ProtectedSharingIdentityStore {
  load(appId: string): Promise<unknown>;
  save(record: ProtectedSharingIdentityV1): Promise<void>;
  /** Atomically inserts a new app record and returns false when one exists. */
  saveIfAbsent?(record: ProtectedSharingIdentityV1): Promise<boolean>;
  delete(appId: string): Promise<void>;
}

export type PasskeyProtectedSharingIdentityProviderOptions = {
  appId: string;
  passkeyProvider: WebPasskeyProvider<CryptoKey>;
  store: ProtectedSharingIdentityStore;
  crypto?: Crypto;
  /** Overrides Web Locks coordination; null disables it for testing. */
  locks?: LockManager | null;
};

/**
 * Persists only passkey-encrypted PKCS#8 private key material. Runtime private
 * keys are re-imported as non-extractable CryptoKeys after every unlock.
 */
export class PasskeyProtectedSharingIdentityProvider {
  private cached: WebCryptoSharingIdentity | null = null;

  constructor(
    private readonly options: PasskeyProtectedSharingIdentityProviderOptions,
  ) {
    if (!options.appId.trim()) throw new TypeError("appId must not be empty.");
  }

  async get(): Promise<WebCryptoSharingIdentity> {
    if (this.cached) return this.cached;
    const stored = await this.options.store.load(this.options.appId);
    if (!stored) {
      throw new SyncKitError(
        "not-found",
        "No protected sharing identity exists for this application.",
      );
    }
    const record = parseProtectedSharingIdentityV1(stored);
    const wrappingKey = await this.options.passkeyProvider.unlockMetadata(
      metadataFromRecord(record),
    );
    this.cached = await unlockProtectedSharingIdentityV1(
      record,
      wrappingKey,
      this.crypto(),
    );
    return this.cached;
  }

  async getOrCreate(): Promise<WebCryptoSharingIdentity> {
    return this.withCreationLock(() => this.getOrCreateUnlocked());
  }

  private async getOrCreateUnlocked(): Promise<WebCryptoSharingIdentity> {
    try {
      return await this.get();
    } catch (error) {
      if (!(error instanceof SyncKitError) || error.code !== "not-found") {
        throw error;
      }
      return this.createUnlocked();
    }
  }

  async create(): Promise<WebCryptoSharingIdentity> {
    return this.withCreationLock(() => this.createUnlocked());
  }

  private async createUnlocked(): Promise<WebCryptoSharingIdentity> {
    if (await this.options.store.load(this.options.appId)) {
      throw new SyncKitError(
        "conflict",
        "A protected sharing identity already exists.",
      );
    }
    const created = await this.options.passkeyProvider.create();
    const protectedIdentity = await createProtectedSharingIdentityV1(
      this.options.appId,
      created.metadata,
      created.key,
      this.crypto(),
    );
    const stored = this.options.store.saveIfAbsent
      ? await this.options.store.saveIfAbsent(protectedIdentity.record)
      : await this.saveAfterCompatibilityRecheck(protectedIdentity.record);
    if (!stored) {
      throw new SyncKitError(
        "conflict",
        "Another context created the protected sharing identity first.",
      );
    }
    this.cached = protectedIdentity.identity;
    return this.cached;
  }

  async delete(): Promise<void> {
    this.clear();
    await this.options.store.delete(this.options.appId);
  }

  async accountBindingCredential(): Promise<{
    credentialId: string;
    credentialPublicKey: JsonWebKey;
  }> {
    const input = await this.options.store.load(this.options.appId);
    const record = parseProtectedSharingIdentityV1(input);
    if (!record.credentialPublicKey) {
      throw new SyncKitError(
        "state",
        "This passkey registration did not expose its ES256 public key.",
      );
    }
    return {
      credentialId: record.credentialId,
      credentialPublicKey: record.credentialPublicKey,
    };
  }

  clear(): void {
    this.cached = null;
    this.options.passkeyProvider.clear();
  }

  private async saveAfterCompatibilityRecheck(
    record: ProtectedSharingIdentityV1,
  ): Promise<boolean> {
    // Backwards compatibility for custom stores predating saveIfAbsent. This
    // narrows but cannot eliminate cross-context races; stores should implement
    // the atomic method when their substrate supports it.
    if (await this.options.store.load(record.appId)) return false;
    await this.options.store.save(record);
    return true;
  }

  private async withCreationLock<T>(operation: () => Promise<T>): Promise<T> {
    const locks =
      this.options.locks === null
        ? undefined
        : this.options.locks ??
          (typeof navigator === "undefined" ? undefined : navigator.locks);
    if (!locks) return await operation();
    return await locks.request<Promise<T>>(
      `sync-kit:protected-sharing-identity:${this.options.appId}`,
      operation,
    );
  }

  private crypto(): Crypto {
    const implementation = this.options.crypto ?? globalThis.crypto;
    if (!implementation?.subtle) {
      throw new SyncKitError(
        "configuration",
        "WebCrypto is required for protected sharing identities.",
      );
    }
    return implementation;
  }
}

export async function createProtectedSharingIdentityV1(
  appId: string,
  metadata: WebPasskeyKeyMetadata,
  wrappingKey: CryptoKey,
  cryptoImplementation: Crypto = globalThis.crypto,
): Promise<{
  identity: WebCryptoSharingIdentity;
  record: ProtectedSharingIdentityV1;
}> {
  if (!appId.trim()) throw new TypeError("appId must not be empty.");
  const { publicKey, packed } = await generateSharingIdentityMaterial(
    cryptoImplementation,
  );
  try {
    return await sealProtectedSharingIdentity(
      appId,
      metadata,
      wrappingKey,
      publicKey,
      packed,
      cryptoImplementation,
    );
  } finally {
    packed.fill(0);
  }
}

/**
 * Re-wraps the exact existing sharing identity under a replacement passkey.
 * Web counterpart of Kotlin's
 * `ProtectedSharingIdentityCrypto.rewrapWithReplacementCredential`.
 *
 * The identity — and so its `keyId`, and every dataset and keyring encrypted
 * to it — is unchanged; only the passkey that protects it is replaced. Use it
 * to move to a new passkey, or to upgrade a record created before
 * `credentialPublicKey` was captured (required for account binding): unlock
 * the old record, register a replacement passkey, then rewrap.
 *
 * The private keys are decrypted and re-sealed as bytes and never become
 * extractable `CryptoKey`s. Persist the returned record atomically; the
 * original stays valid until that save succeeds, so a failed save loses
 * nothing.
 */
export async function rewrapProtectedSharingIdentityV1(
  input: unknown,
  oldWrappingKey: CryptoKey,
  replacementMetadata: WebPasskeyKeyMetadata,
  replacementWrappingKey: CryptoKey,
  cryptoImplementation: Crypto = globalThis.crypto,
): Promise<{
  identity: WebCryptoSharingIdentity;
  record: ProtectedSharingIdentityV1;
}> {
  const record = parseProtectedSharingIdentityV1(input);
  if (!replacementMetadata.credentialPublicKey) {
    throw new SyncKitError(
      "state",
      "The replacement passkey registration did not expose its ES256 public key.",
    );
  }
  const packed = await decryptPrivateKeys(
    record,
    oldWrappingKey,
    cryptoImplementation,
  );
  try {
    const replacement = await sealProtectedSharingIdentity(
      record.appId,
      replacementMetadata,
      replacementWrappingKey,
      record.publicKey,
      packed,
      cryptoImplementation,
    );
    if (replacement.record.publicKey.keyId !== record.publicKey.keyId) {
      throw new SyncKitError(
        "crypto",
        "Credential migration changed the protected sharing identity.",
      );
    }
    return replacement;
  } finally {
    packed.fill(0);
  }
}

async function sealProtectedSharingIdentity(
  appId: string,
  metadata: WebPasskeyKeyMetadata,
  wrappingKey: CryptoKey,
  publicKey: SharingPublicKeyV1,
  packed: Uint8Array,
  cryptoImplementation: Crypto,
): Promise<{
  identity: WebCryptoSharingIdentity;
  record: ProtectedSharingIdentityV1;
}> {
  const nonce = cryptoImplementation.getRandomValues(new Uint8Array(12));
  const header = {
    schemaVersion: 1 as const,
    kind: PROTECTED_SHARING_IDENTITY_KIND,
    appId,
    rpId: metadata.rpId,
    credentialId: metadata.credentialId,
    ...(metadata.credentialPublicKey
      ? { credentialPublicKey: metadata.credentialPublicKey }
      : {}),
    prfInput: bytesToBase64Url(metadata.prfInput),
    kdfSalt: bytesToBase64Url(metadata.kdfSalt),
    nonce: bytesToBase64Url(nonce),
    publicKey,
  };
  const encryptedPrivateKeys = await cryptoImplementation.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: copyBuffer(nonce),
      additionalData: copyBuffer(canonicalAad(header)),
      tagLength: 128,
    },
    wrappingKey,
    copyBuffer(packed),
  );
  const record = {
    ...header,
    encryptedPrivateKeys: bytesToBase64Url(new Uint8Array(encryptedPrivateKeys)),
  };
  return {
    record,
    identity: await importSharingIdentity(record.publicKey, packed, cryptoImplementation),
  };
}

export async function unlockProtectedSharingIdentityV1(
  input: unknown,
  wrappingKey: CryptoKey,
  cryptoImplementation: Crypto = globalThis.crypto,
): Promise<WebCryptoSharingIdentity> {
  const record = parseProtectedSharingIdentityV1(input);
  const plaintext = await decryptPrivateKeys(
    record,
    wrappingKey,
    cryptoImplementation,
  );
  try {
    return await importSharingIdentity(record.publicKey, plaintext, cryptoImplementation);
  } finally {
    plaintext.fill(0);
  }
}

async function decryptPrivateKeys(
  record: ProtectedSharingIdentityV1,
  wrappingKey: CryptoKey,
  cryptoImplementation: Crypto,
): Promise<Uint8Array> {
  try {
    return new Uint8Array(
      await cryptoImplementation.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: copyBuffer(base64UrlToBytes(record.nonce)),
          additionalData: copyBuffer(canonicalAad(protectedIdentityHeader(record))),
          tagLength: 128,
        },
        wrappingKey,
        copyBuffer(base64UrlToBytes(record.encryptedPrivateKeys)),
      ),
    );
  } catch (error) {
    throw asSyncKitError(
      error,
      "key",
      "The passkey could not unlock the protected sharing identity.",
    );
  }
}

export function parseProtectedSharingIdentityV1(
  input: unknown,
): ProtectedSharingIdentityV1 {
  const value =
    typeof input === "string" ? (JSON.parse(input) as unknown) : input;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new SyncKitError(
      "compatibility",
      "The protected sharing identity must be an object.",
    );
  }
  const record = value as Record<string, unknown>;
  if (
    record.schemaVersion !== 1 ||
    record.kind !== PROTECTED_SHARING_IDENTITY_KIND
  ) {
    throw new SyncKitError(
      "compatibility",
      "The protected sharing identity version is unsupported.",
    );
  }
  if (
    record.credentialPublicKey !== undefined &&
    (!record.credentialPublicKey ||
      typeof record.credentialPublicKey !== "object" ||
      Array.isArray(record.credentialPublicKey))
  ) {
    throw new SyncKitError(
      "compatibility",
      "credentialPublicKey must be a JWK object.",
    );
  }
  for (const field of [
    "appId",
    "rpId",
    "credentialId",
    "prfInput",
    "kdfSalt",
    "nonce",
    "encryptedPrivateKeys",
  ]) {
    if (typeof record[field] !== "string" || record[field].length === 0) {
      throw new SyncKitError(
        "compatibility",
        `${field} must be a non-empty string.`,
      );
    }
  }
  if (
    base64UrlToBytes(record.prfInput as string).length !== 32 ||
    base64UrlToBytes(record.kdfSalt as string).length !== 32 ||
    base64UrlToBytes(record.nonce as string).length !== 12
  ) {
    throw new SyncKitError(
      "compatibility",
      "Protected sharing identity cryptographic metadata is malformed.",
    );
  }
  base64UrlToBytes(record.credentialId as string);
  base64UrlToBytes(record.encryptedPrivateKeys as string);
  if (!record.publicKey || typeof record.publicKey !== "object") {
    throw new SyncKitError(
      "compatibility",
      "The protected sharing identity has no public key.",
    );
  }
  return record as ProtectedSharingIdentityV1;
}

export class IndexedDbProtectedSharingIdentityStore
  implements ProtectedSharingIdentityStore
{
  constructor(
    private readonly options: {
      databaseName?: string;
      storeName?: string;
      indexedDB?: IDBFactory;
    } = {},
  ) {}

  async load(appId: string): Promise<unknown> {
    return this.transaction("readonly", (store) => store.get(appId));
  }

  async save(record: ProtectedSharingIdentityV1): Promise<void> {
    await this.transaction("readwrite", (store) => store.put(record));
  }

  async saveIfAbsent(record: ProtectedSharingIdentityV1): Promise<boolean> {
    try {
      await this.transaction("readwrite", (store) => store.add(record));
      return true;
    } catch (error) {
      const cause = (error as { cause?: { name?: string } }).cause;
      if (cause?.name === "ConstraintError") return false;
      throw error;
    }
  }

  async delete(appId: string): Promise<void> {
    await this.transaction("readwrite", (store) => store.delete(appId));
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
          new SyncKitError(
            "state",
            "IndexedDB sharing identity storage failed.",
            { cause: request.error },
          ),
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
          "IndexedDB is required for protected sharing identity storage.",
        ),
      );
    }
    return new Promise((resolve, reject) => {
      const request = indexedDBImplementation.open(
        this.options.databaseName ?? "sync-kit",
        1,
      );
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(this.storeName())) {
          request.result.createObjectStore(this.storeName(), {
            keyPath: "appId",
          });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(
          new SyncKitError(
            "state",
            "IndexedDB sharing identity storage could not be opened.",
            { cause: request.error },
          ),
        );
    });
  }

  private storeName(): string {
    return this.options.storeName ?? "sharing-identities";
  }
}

function metadataFromRecord(
  record: ProtectedSharingIdentityV1,
): WebPasskeyKeyMetadata {
  return {
    credentialId: record.credentialId,
    ...(record.credentialPublicKey
      ? { credentialPublicKey: record.credentialPublicKey }
      : {}),
    rpId: record.rpId,
    prfInput: base64UrlToBytes(record.prfInput),
    kdfSalt: base64UrlToBytes(record.kdfSalt),
  };
}

function protectedIdentityHeader(record: ProtectedSharingIdentityV1) {
  return {
    schemaVersion: record.schemaVersion,
    kind: record.kind,
    appId: record.appId,
    rpId: record.rpId,
    credentialId: record.credentialId,
    ...(record.credentialPublicKey
      ? { credentialPublicKey: record.credentialPublicKey }
      : {}),
    prfInput: record.prfInput,
    kdfSalt: record.kdfSalt,
    nonce: record.nonce,
    publicKey: record.publicKey,
  };
}

