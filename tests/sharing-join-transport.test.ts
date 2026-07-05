import { describe, expect, it } from "vitest";
import {
  findSharingJoinInvitation,
  resolveSharingJoinInvitation,
} from "../src/sharing/join.js";
import {
  createSharingInvitationV1,
  createWebCryptoSharingIdentity,
} from "../src/sharing/web-crypto.js";
import type {
  SharedBackupStorage,
  SharedBackupTransport,
  SharedDatasetFile,
  SharedDatasetDrivePermission,
  SharedDatasetPermission,
  SharedExchangeFile,
  SharedKeyResponseFile,
  VersionedSharedDataset,
} from "../src/sharing/transport.js";
import type { SharingInvitationV1 } from "../src/sharing/index.js";

describe("findSharingJoinInvitation", () => {
  it("returns the invitation file for a join exchange ID", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const invitation = await createSharingInvitationV1(owner, {
      appId: "fixture-app",
      appFolderId: "app-folder",
      recipientDrivePermissionId: "permission-recipient",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
      trustedOwnerKeyId: owner.publicKey.keyId,
    });
    const transport = new JoinLookupTransport();
    await transport.seedInvitation("invitation-1", invitation);

    await expect(
      findSharingJoinInvitation(transport, invitation.exchangeId),
    ).resolves.toEqual({
      invitationFileId: "invitation-1",
      invitation,
    });
  });

  it("resolves a folder-only join link when one invitation exists", async () => {
    const owner = await createWebCryptoSharingIdentity();
    const invitation = await createSharingInvitationV1(owner, {
      appId: "fixture-app",
      appFolderId: "app-folder",
      recipientDrivePermissionId: "permission-recipient",
      requestedGrants: [{ datasetId: "tasks", role: "writer" }],
      trustedOwnerKeyId: owner.publicKey.keyId,
    });
    const transport = new JoinLookupTransport();
    await transport.seedInvitation("invitation-1", invitation);

    await expect(
      resolveSharingJoinInvitation(transport, { appFolderId: "app-folder" }),
    ).resolves.toEqual({
      invitationFileId: "invitation-1",
      invitation,
    });
  });
});

class JoinLookupTransport implements SharedBackupTransport {
  readonly storage: SharedBackupStorage = {
    appFolderId: "app-folder",
    exchangesFolderId: "exchanges-folder",
  };
  private readonly invitations = new Map<string, SharingInvitationV1>();

  async seedInvitation(
    fileId: string,
    invitation: SharingInvitationV1,
  ): Promise<void> {
    this.invitations.set(fileId, invitation);
  }

  ensureStorage(): Promise<SharedBackupStorage> {
    return Promise.resolve(this.storage);
  }

  listDatasets(): Promise<SharedDatasetFile[]> {
    return Promise.resolve([]);
  }

  readDataset(): Promise<VersionedSharedDataset> {
    throw new Error("Not implemented.");
  }

  createDataset(): Promise<VersionedSharedDataset> {
    throw new Error("Not implemented.");
  }

  writeDataset(): Promise<VersionedSharedDataset> {
    throw new Error("Not implemented.");
  }

  grantExchangeAccess(): Promise<{ drivePermissionId: string; appFolderId: string }> {
    throw new Error("Not implemented.");
  }

  createInvitation(): Promise<string> {
    throw new Error("Not implemented.");
  }

  createKeyResponse(): Promise<string> {
    throw new Error("Not implemented.");
  }

  async listExchanges(
    options: {
      exchangeId?: string;
      kind?: SharedExchangeFile["kind"];
    } = {},
  ): Promise<SharedExchangeFile[]> {
    return [...this.invitations.entries()]
      .filter(([, invitation]) =>
        options.exchangeId ? invitation.exchangeId === options.exchangeId : true,
      )
      .map(([fileId, invitation]) => ({
        fileId,
        exchangeId: invitation.exchangeId,
        kind: "invitation" as const,
      }))
      .filter((file) => (options.kind ? file.kind === options.kind : true));
  }

  async readInvitation(fileId: string): Promise<SharingInvitationV1> {
    const invitation = this.invitations.get(fileId);
    if (!invitation) throw new Error(`Missing ${fileId}`);
    return structuredClone(invitation);
  }

  readKeyResponse(): Promise<SharedKeyResponseFile> {
    throw new Error("Not implemented.");
  }

  deleteExchange(): Promise<void> {
    return Promise.resolve();
  }

  setDatasetPermission(): Promise<SharedDatasetPermission> {
    throw new Error("Not implemented.");
  }

  removeDatasetPermission(): Promise<void> {
    return Promise.resolve();
  }

  listDatasetPermissions(): Promise<SharedDatasetDrivePermission[]> {
    return Promise.resolve([]);
  }

  listDatasetHeads() {
    return Promise.resolve([]);
  }
}
