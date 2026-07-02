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
  createSharingPublicKeyV1,
  type WebCryptoSharingIdentity,
} from "./web-crypto.js";

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
  delete(appId: string): Promise<void>;
}

export type PasskeyProtectedSharingIdentityProviderOptions = {
  appId: string;
  passkeyProvider: WebPasskeyProvider<CryptoKey>;
  store: ProtectedSharingIdentityStore;
  crypto?: Crypto;
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
    try {
      return await this.get();
    } catch (error) {
      if (!(error instanceof SyncKitError) || error.code !== "not-found") {
        throw error;
      }
      return this.create();
    }
  }

  async create(): Promise<WebCryptoSharingIdentity> {
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
    await this.options.store.save(protectedIdentity.record);
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
  const encryption = await cryptoImplementation.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const signing = await cryptoImplementation.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const encryptionPublicKey = bytesToBase64Url(
    new Uint8Array(
      await cryptoImplementation.subtle.exportKey("raw", encryption.publicKey),
    ),
  );
  const signingPublicKey = bytesToBase64Url(
    new Uint8Array(
      await cryptoImplementation.subtle.exportKey("raw", signing.publicKey),
    ),
  );
  const publicKey = await createSharingPublicKeyV1(
    encryptionPublicKey,
    signingPublicKey,
    cryptoImplementation,
  );
  const encryptionPrivate = new Uint8Array(
    await cryptoImplementation.subtle.exportKey("pkcs8", encryption.privateKey),
  );
  const signingPrivate = new Uint8Array(
    await cryptoImplementation.subtle.exportKey("pkcs8", signing.privateKey),
  );
  const packed = packPrivateKeys(encryptionPrivate, signingPrivate);
  encryptionPrivate.fill(0);
  signingPrivate.fill(0);
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
  try {
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
      encryptedPrivateKeys: bytesToBase64Url(
        new Uint8Array(encryptedPrivateKeys),
      ),
    };
    return {
      record,
      identity: await importIdentity(record, packed, cryptoImplementation),
    };
  } finally {
    packed.fill(0);
  }
}

export async function unlockProtectedSharingIdentityV1(
  input: unknown,
  wrappingKey: CryptoKey,
  cryptoImplementation: Crypto = globalThis.crypto,
): Promise<WebCryptoSharingIdentity> {
  const record = parseProtectedSharingIdentityV1(input);
  const header = protectedIdentityHeader(record);
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await cryptoImplementation.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: copyBuffer(base64UrlToBytes(record.nonce)),
          additionalData: copyBuffer(canonicalAad(header)),
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
  try {
    return await importIdentity(record, plaintext, cryptoImplementation);
  } finally {
    plaintext.fill(0);
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

async function importIdentity(
  record: ProtectedSharingIdentityV1,
  packed: Uint8Array,
  cryptoImplementation: Crypto,
): Promise<WebCryptoSharingIdentity> {
  const [encryptionPrivate, signingPrivate] = unpackPrivateKeys(packed);
  try {
    const identity = {
      publicKey: record.publicKey,
      encryptionPrivateKey: await cryptoImplementation.subtle.importKey(
        "pkcs8",
        copyBuffer(encryptionPrivate),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      ),
      signingPrivateKey: await cryptoImplementation.subtle.importKey(
        "pkcs8",
        copyBuffer(signingPrivate),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"],
      ),
    };
    const expected = await createSharingPublicKeyV1(
      record.publicKey.encryptionPublicKey,
      record.publicKey.signingPublicKey,
      cryptoImplementation,
    );
    if (expected.keyId !== record.publicKey.keyId) {
      throw new SyncKitError(
        "key",
        "The protected sharing identity public-key fingerprint is invalid.",
      );
    }
    return identity;
  } finally {
    encryptionPrivate.fill(0);
    signingPrivate.fill(0);
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

function packPrivateKeys(
  encryptionPrivate: Uint8Array,
  signingPrivate: Uint8Array,
): Uint8Array {
  const packed = new Uint8Array(4 + encryptionPrivate.length + signingPrivate.length);
  new DataView(packed.buffer).setUint32(0, encryptionPrivate.length);
  packed.set(encryptionPrivate, 4);
  packed.set(signingPrivate, 4 + encryptionPrivate.length);
  return packed;
}

function unpackPrivateKeys(packed: Uint8Array): [Uint8Array, Uint8Array] {
  if (packed.length < 5) {
    throw new SyncKitError(
      "compatibility",
      "Protected sharing private-key material is malformed.",
    );
  }
  const encryptionLength = new DataView(
    packed.buffer,
    packed.byteOffset,
    packed.byteLength,
  ).getUint32(0);
  if (encryptionLength === 0 || 4 + encryptionLength >= packed.length) {
    throw new SyncKitError(
      "compatibility",
      "Protected sharing private-key material is malformed.",
    );
  }
  return [
    packed.slice(4, 4 + encryptionLength),
    packed.slice(4 + encryptionLength),
  ];
}
