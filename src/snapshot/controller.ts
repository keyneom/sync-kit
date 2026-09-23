import type {
  AuthorizationProvider,
  CloudStore,
  EnvelopeCrypto,
  KeyProvider,
  SnapshotRecoveryCrypto,
  SyncCodec,
  SyncReason,
  SyncResult,
} from "../core/types.js";
import { SyncKitError } from "../core/errors.js";

export type SnapshotSyncOptions<T, E, K, M, A> = {
  appId: string;
  codec: SyncCodec<T>;
  envelopeCrypto: EnvelopeCrypto<T, E, K, M>;
  keyProvider: KeyProvider<E, K, M>;
  authorizationProvider: AuthorizationProvider<A>;
  cloudStore: CloudStore<E, A>;
  readLocal(): Promise<T> | T;
  applyMerged(value: T): Promise<void> | void;
  envelopeUpdatedAt(envelope: E): string;
};

export interface SnapshotSyncController<T> {
  setup(): Promise<SyncResult<T>>;
  enable(): Promise<SyncResult<T>>;
  sync(reason: SyncReason): Promise<SyncResult<T>>;
  reset(): Promise<SyncResult<T>>;
  delete(): Promise<void>;
  /**
   * Adds or replaces the snapshot's recovery code — or removes it, with null.
   * Unlocks with the passkey. Upgrades a v1 snapshot to v2, which devices
   * whose profile does not read v2 cannot open; see docs/snapshot-recovery.md.
   * Generate codes with `generateRecoveryCode`; never accept a chosen one.
   */
  setRecoveryCode(recoveryCode: string | null): Promise<void>;
  /**
   * Opens the snapshot with its recovery code when the passkey is lost,
   * registers a new passkey, merges with local state, and locks the snapshot
   * under the new passkey. The recovery code keeps working afterwards.
   */
  recover(recoveryCode: string): Promise<SyncResult<T>>;
  /** Explicit, reversible version change. Moving to 1 removes any recovery code. */
  migrateVersion(version: 1 | 2): Promise<void>;
  lock(): void;
  operationInProgress(): boolean;
}

export function createSnapshotSync<T, E, K, M, A>(
  options: SnapshotSyncOptions<T, E, K, M, A>,
): SnapshotSyncController<T> {
  let operationTail: Promise<void> = Promise.resolve();
  let operationCount = 0;
  let queuedChange: Promise<SyncResult<T>> | null = null;

  function operationInProgress(): boolean {
    return operationCount > 0;
  }

  function runExclusive<R>(operation: () => Promise<R>): Promise<R> {
    operationCount += 1;
    const result = operationTail.then(operation);
    operationTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result.finally(() => {
      operationCount -= 1;
    });
  }

  async function findRequired(
    authorization: A,
  ): Promise<{ fileId: string; envelope: E }> {
    const existing = await options.cloudStore.find(
      options.appId,
      authorization,
    );
    if (!existing) {
      throw new SyncKitError(
        "not-found",
        `No ${options.appId} encrypted snapshot was found.`,
      );
    }
    return existing;
  }

  async function setupNow(): Promise<SyncResult<T>> {
    const authorization = await options.authorizationProvider.authorize();
    if (await options.cloudStore.find(options.appId, authorization)) {
      throw new SyncKitError(
        "state",
        `A ${options.appId} encrypted snapshot already exists.`,
      );
    }
    const local = await options.readLocal();
    const created = await options.keyProvider.create({ appId: options.appId });
    const envelope = await options.envelopeCrypto.encrypt(
      local,
      created.key,
      created.metadata,
    );
    const fileId = await options.cloudStore.write(
      options.appId,
      envelope,
      authorization,
    );
    return {
      operation: "setup",
      outcome: "created",
      fileId,
      syncedAt: options.envelopeUpdatedAt(envelope),
      value: local,
    };
  }

  async function mergeNow(
    operation: "enable" | "sync",
  ): Promise<SyncResult<T>> {
    const authorization = await options.authorizationProvider.authorize();
    const existing = await findRequired(authorization);
    const key = await options.keyProvider.unlock(existing.envelope);
    let remote: T;
    try {
      remote = await options.envelopeCrypto.decrypt(existing.envelope, key);
    } catch (error) {
      options.keyProvider.clear();
      throw error;
    }
    const local = await options.readLocal();
    const merged = options.codec.merge(local, remote);
    const cloudChanged =
      options.codec.fingerprint(merged) !== options.codec.fingerprint(remote);
    let syncedAt = options.envelopeUpdatedAt(existing.envelope);
    if (cloudChanged) {
      const metadata = options.envelopeCrypto.metadataFromEnvelope(
        existing.envelope,
      );
      const envelope = await options.envelopeCrypto.encrypt(
        merged,
        key,
        metadata,
      );
      await options.cloudStore.write(
        options.appId,
        envelope,
        authorization,
        existing.fileId,
      );
      syncedAt = options.envelopeUpdatedAt(envelope);
    }
    await options.applyMerged(merged);
    return {
      operation,
      outcome: cloudChanged ? "merged" : "unchanged",
      fileId: existing.fileId,
      syncedAt,
      value: merged,
    };
  }

  async function resetNow(): Promise<SyncResult<T>> {
    const authorization = await options.authorizationProvider.authorize();
    const existing = await findRequired(authorization);
    options.keyProvider.clear();
    const local = await options.readLocal();
    const created = await options.keyProvider.create({ appId: options.appId });
    const envelope = await options.envelopeCrypto.encrypt(
      local,
      created.key,
      created.metadata,
    );
    await options.cloudStore.write(
      options.appId,
      envelope,
      authorization,
      existing.fileId,
    );
    return {
      operation: "reset",
      outcome: "reset",
      fileId: existing.fileId,
      syncedAt: options.envelopeUpdatedAt(envelope),
      value: local,
    };
  }

  function recoveryCrypto(): SnapshotRecoveryCrypto<T, E, K, M> {
    const crypto = options.envelopeCrypto as Partial<SnapshotRecoveryCrypto<T, E, K, M>>;
    if (
      !crypto.setRecoveryCode ||
      !crypto.decryptWithRecoveryCode ||
      !crypto.relockWithRecoveryCode ||
      !crypto.migrate
    ) {
      throw new SyncKitError(
        "configuration",
        "This envelope crypto does not support recovery codes; use createV1EnvelopeCrypto.",
      );
    }
    return crypto as SnapshotRecoveryCrypto<T, E, K, M>;
  }

  /** Rewrites the snapshot in place with a passkey-unlocked transform. */
  async function rewriteNow(
    transform: (envelope: E, key: K) => Promise<E>,
  ): Promise<void> {
    const authorization = await options.authorizationProvider.authorize();
    const existing = await findRequired(authorization);
    const key = await options.keyProvider.unlock(existing.envelope);
    const envelope = await transform(existing.envelope, key);
    await options.cloudStore.write(options.appId, envelope, authorization, existing.fileId);
  }

  async function recoverNow(recoveryCode: string): Promise<SyncResult<T>> {
    const crypto = recoveryCrypto();
    const authorization = await options.authorizationProvider.authorize();
    const existing = await findRequired(authorization);
    const remote = await crypto.decryptWithRecoveryCode(existing.envelope, recoveryCode);
    const merged = options.codec.merge(await options.readLocal(), remote);
    options.keyProvider.clear();
    const created = await options.keyProvider.create({ appId: options.appId });
    const envelope = await crypto.relockWithRecoveryCode(
      existing.envelope,
      recoveryCode,
      created,
      merged,
    );
    await options.cloudStore.write(options.appId, envelope, authorization, existing.fileId);
    await options.applyMerged(merged);
    return {
      operation: "recover",
      outcome: "recovered",
      fileId: existing.fileId,
      syncedAt: options.envelopeUpdatedAt(envelope),
      value: merged,
    };
  }

  function setRecoveryCode(recoveryCode: string | null): Promise<void> {
    return runExclusive(() => {
      const crypto = recoveryCrypto();
      return rewriteNow((envelope, key) => crypto.setRecoveryCode(envelope, key, recoveryCode));
    });
  }

  function recover(recoveryCode: string): Promise<SyncResult<T>> {
    return runExclusive(() => recoverNow(recoveryCode));
  }

  function migrateVersion(version: 1 | 2): Promise<void> {
    return runExclusive(() => {
      const crypto = recoveryCrypto();
      return rewriteNow((envelope, key) => crypto.migrate(envelope, key, version));
    });
  }

  function setup(): Promise<SyncResult<T>> {
    return runExclusive(setupNow);
  }

  function enable(): Promise<SyncResult<T>> {
    return runExclusive(() => mergeNow("enable"));
  }

  function sync(reason: SyncReason): Promise<SyncResult<T>> {
    if (operationInProgress()) {
      if (reason !== "change") {
        return Promise.resolve({
          operation: "sync",
          outcome: "coalesced",
          fileId: null,
          syncedAt: null,
          value: null,
        });
      }
      if (queuedChange) return queuedChange;
      const pending = runExclusive(() => {
        queuedChange = null;
        return mergeNow("sync");
      });
      queuedChange = pending;
      return pending;
    }
    return runExclusive(() => mergeNow("sync"));
  }

  function reset(): Promise<SyncResult<T>> {
    return runExclusive(resetNow);
  }

  function deleteSnapshot(): Promise<void> {
    return runExclusive(async () => {
      const authorization = await options.authorizationProvider.authorize();
      const existing = await options.cloudStore.find(
        options.appId,
        authorization,
      );
      if (existing) {
        if (!options.cloudStore.delete) {
          throw new SyncKitError(
            "configuration",
            "This cloud store does not support deletion.",
          );
        }
        await options.cloudStore.delete(
          options.appId,
          existing.fileId,
          authorization,
        );
      }
      lock();
    });
  }

  function lock(): void {
    options.keyProvider.clear();
    options.authorizationProvider.clear();
  }

  return {
    setup,
    enable,
    sync,
    reset,
    delete: deleteSnapshot,
    setRecoveryCode,
    recover,
    migrateVersion,
    lock,
    operationInProgress,
  };
}
