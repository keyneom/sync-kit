export type SyncReason = "startup" | "foreground" | "change" | "manual";
export type SnapshotOperation = "setup" | "enable" | "sync" | "reset";

export type Authorization = {
  accessToken: string;
  expiresAt?: number;
};

export interface AuthorizationProvider<A = Authorization> {
  authorize(): Promise<A>;
  clear(): void;
}

export type StoredEnvelope<E> = {
  fileId: string;
  envelope: E;
};

export interface CloudStore<E, A = Authorization> {
  find(appId: string, authorization: A): Promise<StoredEnvelope<E> | null>;
  write(
    appId: string,
    envelope: E,
    authorization: A,
    existingId?: string,
  ): Promise<string>;
  delete?(appId: string, fileId: string, authorization: A): Promise<void>;
}

export type KeyCreationContext = {
  appId: string;
};

export type CreatedKey<M, K> = {
  metadata: M;
  key: K;
};

export interface KeyProvider<E, K, M> {
  create(context: KeyCreationContext): Promise<CreatedKey<M, K>>;
  unlock(envelope: E): Promise<K>;
  clear(): void;
}

export interface EnvelopeCrypto<T, E, K, M> {
  encrypt(value: T, key: K, metadata: M): Promise<E>;
  decrypt(envelope: E, key: K): Promise<T>;
  metadataFromEnvelope(envelope: E): M;
}

export interface SyncCodec<T> {
  serialize(value: T): unknown;
  parse(value: unknown): T;
  merge(local: T, remote: T): T;
  fingerprint(value: T): string;
  updatedAt?(value: T): string;
}

export type SyncOutcome =
  | "created"
  | "merged"
  | "unchanged"
  | "reset"
  | "coalesced";

export type SyncResult<T> = {
  operation: SnapshotOperation;
  outcome: SyncOutcome;
  fileId: string | null;
  syncedAt: string | null;
  value: T | null;
};
