import type { Authorization } from "../core/types.js";
import { GoogleDriveAppDataStore } from "../stores/google-drive/index.js";
import {
  parseProtectedSharingIdentityV1,
  type ProtectedSharingIdentityStore,
  type ProtectedSharingIdentityV1,
} from "./web-passkey.js";

export type DriveAppDataProtectedSharingIdentityStoreOptions = {
  /**
   * Supplies a Drive authorization scoped to `drive.appdata`. The same Google
   * account on any device returns the same private app-data folder, which is
   * how a single sharing identity follows the user across devices.
   */
  authorization(): Promise<Authorization>;
  /** Overrides the app-data filename derived from the app id. */
  filename?(appId: string): string;
  drive?: GoogleDriveAppDataStore;
};

/**
 * Hosts the passkey-wrapped sharing identity in the signed-in Google account's
 * private `drive.appdata` folder instead of device-local storage. Because the
 * record is already AES-GCM-encrypted with the passkey PRF secret, app-data is
 * a plaintext-safe transport: Drive only ever sees an opaque JSON blob whose
 * `encryptedPrivateKeys` field it cannot read.
 *
 * The single-user, multi-device continuity this restores is deliberately
 * distinct from the sharing (multi-user) protocol: the identity here is one
 * account's own key, replicated to its own devices, never granted to another
 * participant.
 */
export class DriveAppDataProtectedSharingIdentityStore
  implements ProtectedSharingIdentityStore
{
  private readonly drive: GoogleDriveAppDataStore;

  constructor(
    private readonly options: DriveAppDataProtectedSharingIdentityStoreOptions,
  ) {
    this.drive = options.drive ?? new GoogleDriveAppDataStore();
  }

  async load(appId: string): Promise<ProtectedSharingIdentityV1 | null> {
    const authorization = await this.options.authorization();
    const found = await this.drive.find(this.filename(appId), authorization);
    if (!found) return null;
    const text = await this.drive.readText(found.fileId, authorization);
    return parseProtectedSharingIdentityV1(text);
  }

  async save(record: ProtectedSharingIdentityV1): Promise<void> {
    const authorization = await this.options.authorization();
    const name = this.filename(record.appId);
    const found = await this.drive.find(name, authorization);
    await this.drive.write(name, JSON.stringify(record), authorization, {
      ...(found ? { existingId: found.fileId } : {}),
      contentType: "application/json",
    });
  }

  async delete(appId: string): Promise<void> {
    const authorization = await this.options.authorization();
    const found = await this.drive.find(this.filename(appId), authorization);
    if (found) await this.drive.delete(found.fileId, authorization);
  }

  private filename(appId: string): string {
    return (
      this.options.filename?.(appId) ?? `sync-kit-sharing-identity-${appId}.json`
    );
  }
}
