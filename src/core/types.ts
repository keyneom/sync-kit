export type SyncReason = "startup" | "foreground" | "change" | "manual";
export type SnapshotOperation = "setup" | "enable" | "sync" | "reset" | "recover";

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

/**
 * Snapshot recovery codes and explicit version migration, implemented by
 * `createV1EnvelopeCrypto`. A snapshot controller exposes `setRecoveryCode`,
 * `recover`, and `migrateVersion` when its envelope crypto has these. See
 * docs/snapshot-recovery.md.
 */
export interface SnapshotRecoveryCrypto<T, E, K, M> {
  /** Adds, replaces, or (with null) removes the recovery lock. Upgrades a v1 snapshot to v2. */
  setRecoveryCode(envelope: E, key: K, recoveryCode: string | null): Promise<E>;
  decryptWithRecoveryCode(envelope: E, recoveryCode: string): Promise<T>;
  /** Opens with the recovery code and locks `value` under a new passkey, keeping the recovery lock. */
  relockWithRecoveryCode(
    envelope: E,
    recoveryCode: string,
    replacement: CreatedKey<M, K>,
    value: T,
  ): Promise<E>;
  /** Explicit, reversible version change. Moving to 1 removes any recovery lock. */
  migrate(envelope: E, key: K, version: 1 | 2): Promise<E>;
}

export interface KeyProvider<E, K, M> {
  /**
   * Establishes a new key. The returned `key` is the **derived content key**,
   * ready for {@link EnvelopeCrypto.encrypt} — see {@link KeyProvider.unlock}.
   */
  create(context: KeyCreationContext): Promise<CreatedKey<M, K>>;
  /**
   * Returns the **derived content key**, not the raw secret it came from.
   *
   * Passkey-backed providers run the PRF ceremony and then the envelope's KDF
   * over its `kdfSalt` before returning. Pass the result straight to
   * {@link EnvelopeCrypto.decrypt}; **do not derive from it again.** Deriving a
   * second time yields `KDF(KDF(secret, salt), salt)`, which differs from what
   * every other platform holds, so the envelope fails to open in a way that
   * looks like the wrong credential was returned rather than a key-derivation
   * mismatch.
   */
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
  | "recovered"
  | "coalesced";

export type SyncResult<T> = {
  operation: SnapshotOperation;
  outcome: SyncOutcome;
  fileId: string | null;
  syncedAt: string | null;
  value: T | null;
};
