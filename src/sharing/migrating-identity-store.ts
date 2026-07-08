import {
  parseProtectedSharingIdentityV1,
  type ProtectedSharingIdentityStore,
  type ProtectedSharingIdentityV1,
} from "./web-passkey.js";

export type MigratingProtectedSharingIdentityStoreOptions = {
  /** Authoritative store (e.g. `drive.appdata`), read first and always written. */
  primary: ProtectedSharingIdentityStore;
  /**
   * Pre-existing device-local store (e.g. IndexedDB / EncryptedSharedPreferences).
   * Read only as a fallback; its blob is promoted to `primary` on first hit.
   */
  legacy: ProtectedSharingIdentityStore;
};

/**
 * Bridges a device that already holds a passkey-wrapped identity in local
 * storage to the app-data-hosted substrate without regenerating it. On the
 * first load after upgrade the legacy blob is promoted to the primary store,
 * after which the primary store is authoritative and local storage is only a
 * cache the consumer may keep for a hot path.
 *
 * Promotion is best-effort: if the primary write fails (offline, revoked
 * scope) the legacy identity is still returned, so a returning user never
 * silently generates a fresh identity and loses access to their dataset.
 */
export class MigratingProtectedSharingIdentityStore
  implements ProtectedSharingIdentityStore
{
  constructor(
    private readonly options: MigratingProtectedSharingIdentityStoreOptions,
  ) {}

  async load(appId: string): Promise<ProtectedSharingIdentityV1 | null> {
    const primary = await this.options.primary.load(appId);
    if (primary) return parseProtectedSharingIdentityV1(primary);
    const legacy = await this.options.legacy.load(appId);
    if (!legacy) return null;
    const record = parseProtectedSharingIdentityV1(legacy);
    await this.options.primary.save(record).catch(() => undefined);
    return record;
  }

  async save(record: ProtectedSharingIdentityV1): Promise<void> {
    await this.options.primary.save(record);
  }

  async delete(appId: string): Promise<void> {
    await this.options.primary.delete(appId);
    await this.options.legacy.delete(appId).catch(() => undefined);
  }
}
