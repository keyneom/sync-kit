import type {
  Authorization,
  AuthorizationProvider,
} from "../../core/types.js";
import { SyncKitError } from "../../core/errors.js";
import {
  parseSharedBackupEnvelopeV1,
  parseSharingInvitationV1,
  parseSharingPublicKeyResponseV1,
  type SharedBackupEnvelopeV1,
  type SharingInvitationV1,
  type SharingPublicKeyResponseV1,
  type SharingRole,
} from "../../sharing/index.js";
import type {
  SharedBackupStorage,
  SharedBackupTransport,
  SharedDatasetDrivePermission,
  SharedDatasetFile,
  SharedDatasetHead,
  SharedDatasetPermission,
  SharedExchangeFile,
  SharedKeyResponseFile,
  VersionedSharedDataset,
} from "../../sharing/transport.js";
import {
  assertDriveFileProvenance,
  ensureGoogleDriveSyncKitFolder,
  GoogleDriveFileStore,
  SYNC_KIT_APP_ID_PROPERTY,
  SYNC_KIT_DATASET_ID_PROPERTY,
  SYNC_KIT_KIND_PROPERTY,
  SYNC_KIT_PROTOCOL_PROPERTY,
  type DriveFileMetadata,
} from "./index.js";

const SHARING_PROTOCOL = "sharing-v1";

export type GoogleDriveSharedBackupTransportOptions = {
  appId: string;
  authorizationProvider: AuthorizationProvider<Authorization>;
  folderName?: string;
  parentFolderId?: string;
  selectedAppFolderId?: string;
  drive?: GoogleDriveFileStore;
};

/**
 * Backendless Google Drive implementation of the shared-backup transport.
 * Authorization, encryption, and permission changes all happen in the client.
 */
export class GoogleDriveSharedBackupTransport
  implements SharedBackupTransport
{
  private readonly drive: GoogleDriveFileStore;
  private storagePromise: Promise<SharedBackupStorage> | null = null;

  constructor(
    private readonly options: GoogleDriveSharedBackupTransportOptions,
  ) {
    if (!options.appId.trim()) throw new TypeError("appId must not be empty.");
    this.drive = options.drive ?? new GoogleDriveFileStore();
  }

  async ensureStorage(): Promise<SharedBackupStorage> {
    this.storagePromise ??= this.ensureStorageNow().catch((error: unknown) => {
      this.storagePromise = null;
      throw error;
    });
    return this.storagePromise;
  }

  async listDatasets(): Promise<SharedDatasetFile[]> {
    const authorization = await this.authorize();
    const storage = await this.ensureStorage();
    const files = await this.listAll(authorization, {
      parentId: storage.appFolderId,
      appProperties: this.properties("dataset"),
    });
    return files.map((file) => ({
      datasetId: requiredProperty(
        file,
        SYNC_KIT_DATASET_ID_PROPERTY,
        "dataset",
      ),
      fileId: file.fileId,
      name: file.name,
      ...(file.capabilities?.canEdit === undefined
        ? {}
        : { canEdit: file.capabilities.canEdit }),
    }));
  }

  async readDataset(fileId: string): Promise<VersionedSharedDataset> {
    const authorization = await this.authorize();
    const metadata = await this.drive.get(fileId, authorization);
    this.assertManagedFile(metadata, "dataset");
    const datasetId = requiredProperty(
      metadata,
      SYNC_KIT_DATASET_ID_PROPERTY,
      "dataset",
    );
    const document = await this.drive.readTextVersioned(fileId, authorization);
    // Drive v3 rarely exposes HTTP ETags (and browsers may hide them behind
    // CORS), so fall back to the metadata change tokens. If-Match is only
    // usable with a real ETag; writeDataset compensates with a pre-write
    // freshness check when the token is not one.
    const version =
      document.etag ?? metadata.etag ?? metadata.headRevisionId ?? metadata.version;
    if (!version) {
      throw new SyncKitError(
        "state",
        "Google Drive did not expose a change token for the dataset; a safe conditional write is unavailable.",
      );
    }
    const envelope = parseSharedBackupEnvelopeV1(document.content);
    if (
      envelope.appId !== this.options.appId ||
      envelope.backupId !== datasetId
    ) {
      throw new SyncKitError(
        "compatibility",
        "The Drive dataset metadata does not match its encrypted envelope.",
      );
    }
    return {
      datasetId,
      fileId,
      name: metadata.name,
      ...(metadata.capabilities?.canEdit === undefined
        ? {}
        : { canEdit: metadata.capabilities.canEdit }),
      envelope,
      version,
    };
  }

  async createDataset(
    datasetId: string,
    envelope: SharedBackupEnvelopeV1,
  ): Promise<VersionedSharedDataset> {
    requireNonEmpty(datasetId, "datasetId");
    this.assertEnvelopeDataset(datasetId, envelope);
    const authorization = await this.authorize();
    const storage = await this.ensureStorage();
    const fileId = await this.drive.create(
      `${datasetId}.sync-kit.json`,
      JSON.stringify(envelope),
      authorization,
      {
        parentId: storage.appFolderId,
        contentType: "application/json",
        appProperties: {
          ...this.properties("dataset"),
          [SYNC_KIT_DATASET_ID_PROPERTY]: datasetId,
        },
      },
    );
    try {
      return await this.readDataset(fileId);
    } catch (error) {
      // Best-effort rollback: an orphan dataset would block every future
      // createDataset for this id with "already exists".
      try {
        await this.drive.delete(fileId, authorization);
      } catch {
        // Keep the original failure.
      }
      throw error;
    }
  }

  async writeDataset(
    current: VersionedSharedDataset,
    envelope: SharedBackupEnvelopeV1,
  ): Promise<VersionedSharedDataset> {
    this.assertEnvelopeDataset(current.datasetId, envelope);
    if (envelope.parentRevisionId !== current.envelope.revisionId) {
      throw new SyncKitError(
        "conflict",
        "The new dataset revision does not descend from the version being replaced.",
      );
    }
    const authorization = await this.authorize();
    const ifMatch = isHttpEtag(current.version) ? current.version : undefined;
    if (!ifMatch) {
      // Without an ETag the upload cannot be conditional, so verify the file
      // has not moved past the version we read just before writing.
      const head = await this.drive.get(current.fileId, authorization);
      const headToken = head.etag ?? head.headRevisionId ?? head.version;
      if (headToken && headToken !== current.version) {
        throw new SyncKitError(
          "conflict",
          "The Drive dataset changed after it was last read.",
        );
      }
    }
    const written = await this.drive.write(
      current.fileId,
      JSON.stringify(envelope),
      authorization,
      {
        contentType: "application/json",
        ...(ifMatch ? { ifMatch } : {}),
      },
    );
    if (!written.etag) return this.readDataset(current.fileId);
    return {
      ...current,
      envelope,
      version: written.etag,
    };
  }

  async grantExchangeAccess(
    emailAddress: string,
    options: { sendNotificationEmail?: boolean; emailMessage?: string } = {},
  ): Promise<{ drivePermissionId: string; appFolderId: string }> {
    requireNonEmpty(emailAddress, "emailAddress");
    const authorization = await this.authorize();
    const storage = await this.ensureStorage();
    const appPermissionId = await this.drive.share(
      storage.appFolderId,
      emailAddress,
      "reader",
      authorization,
      options,
    );
    const exchangePermissionId = await this.drive.share(
      storage.exchangesFolderId,
      emailAddress,
      "writer",
      authorization,
      { sendNotificationEmail: false },
    );
    if (exchangePermissionId !== appPermissionId) {
      throw new SyncKitError(
        "provider",
        "Google Drive returned inconsistent permission IDs for one account.",
      );
    }
    return {
      drivePermissionId: appPermissionId,
      appFolderId: storage.appFolderId,
    };
  }

  async createInvitation(invitation: SharingInvitationV1): Promise<string> {
    if (invitation.appId !== this.options.appId) {
      throw new SyncKitError(
        "compatibility",
        "The invitation belongs to another application.",
      );
    }
    const authorization = await this.authorize();
    const storage = await this.ensureStorage();
    if (invitation.appFolderId !== storage.appFolderId) {
      throw new SyncKitError(
        "compatibility",
        "The invitation references another app folder.",
      );
    }
    return this.drive.create(
      `${invitation.exchangeId}-invitation.json`,
      JSON.stringify(invitation),
      authorization,
      {
        parentId: storage.exchangesFolderId,
        contentType: "application/json",
        appProperties: {
          ...this.properties("invitation"),
          "sync-kit-exchange-id": invitation.exchangeId,
        },
      },
    );
  }

  async createKeyResponse(
    response: SharingPublicKeyResponseV1,
  ): Promise<string> {
    if (response.appId !== this.options.appId) {
      throw new SyncKitError(
        "compatibility",
        "The key response belongs to another application.",
      );
    }
    const authorization = await this.authorize();
    const storage = await this.ensureStorage();
    return this.drive.create(
      `${response.exchangeId}-${response.keyId}-response.json`,
      JSON.stringify(response),
      authorization,
      {
        parentId: storage.exchangesFolderId,
        contentType: "application/json",
        appProperties: {
          ...this.properties("key-response"),
          "sync-kit-exchange-id": response.exchangeId,
          "sync-kit-key-id": response.keyId,
        },
      },
    );
  }

  async listExchanges(
    options: {
      exchangeId?: string;
      kind?: SharedExchangeFile["kind"];
    } = {},
  ): Promise<SharedExchangeFile[]> {
    const authorization = await this.authorize();
    const storage = await this.ensureStorage();
    const files = await this.listAll(authorization, {
      parentId: storage.exchangesFolderId,
      appProperties: {
        [SYNC_KIT_APP_ID_PROPERTY]: this.options.appId,
        [SYNC_KIT_PROTOCOL_PROPERTY]: SHARING_PROTOCOL,
        ...(options.kind
          ? { [SYNC_KIT_KIND_PROPERTY]: options.kind }
          : {}),
        ...(options.exchangeId
          ? { "sync-kit-exchange-id": options.exchangeId }
          : {}),
      },
    });
    return files.map((file) => {
      const kind = requiredProperty(file, SYNC_KIT_KIND_PROPERTY, "exchange");
      if (kind !== "invitation" && kind !== "key-response") {
        throw new SyncKitError(
          "compatibility",
          "A managed exchange file has an unsupported kind.",
        );
      }
      const keyId = file.appProperties?.["sync-kit-key-id"];
      return {
        fileId: file.fileId,
        exchangeId: requiredProperty(
          file,
          "sync-kit-exchange-id",
          "exchange",
        ),
        kind,
        ...(keyId ? { keyId } : {}),
        ...(file.createdTime ? { createdTime: file.createdTime } : {}),
      };
    });
  }

  async readInvitation(fileId: string): Promise<SharingInvitationV1> {
    const authorization = await this.authorize();
    const metadata = await this.drive.get(fileId, authorization);
    this.assertManagedFile(metadata, "invitation");
    return parseSharingInvitationV1(
      await this.drive.readText(fileId, authorization),
    );
  }

  async readKeyResponse(
    fileId: string,
    expectedDrivePermissionId: string,
  ): Promise<SharedKeyResponseFile> {
    const authorization = await this.authorize();
    const metadata = await this.drive.get(fileId, authorization);
    this.assertManagedFile(metadata, "key-response");
    assertDriveFileProvenance(metadata, {
      permissionId: expectedDrivePermissionId,
    });
    const response = parseSharingPublicKeyResponseV1(
      await this.drive.readText(fileId, authorization),
    );
    return {
      fileId,
      response,
      ownerPermissionId: expectedDrivePermissionId,
    };
  }

  async deleteExchange(fileId: string): Promise<void> {
    await this.drive.delete(fileId, await this.authorize());
  }

  async setDatasetPermission(
    fileId: string,
    emailAddress: string,
    role: Exclude<SharingRole, "owner">,
    options: {
      existingDirectPermissionId?: string;
      hasInheritedReadAccess?: boolean;
    } = {},
  ): Promise<SharedDatasetPermission> {
    const driveRole = role === "viewer" ? "reader" : "writer";
    if (options.existingDirectPermissionId) {
      await this.drive.updatePermission(
        fileId,
        options.existingDirectPermissionId,
        driveRole,
        await this.authorize(),
      );
      return {
        permissionId: options.existingDirectPermissionId,
        role: driveRole,
      };
    }
    if (driveRole === "reader" && options.hasInheritedReadAccess) {
      return { role: "reader" };
    }
    const permissionId = await this.drive.share(
      fileId,
      emailAddress,
      driveRole,
      await this.authorize(),
      { sendNotificationEmail: false },
    );
    return { permissionId, role: driveRole };
  }

  async removeDatasetPermission(
    fileId: string,
    permissionId: string,
  ): Promise<void> {
    await this.drive.removePermission(
      fileId,
      permissionId,
      await this.authorize(),
    );
  }

  async listDatasetPermissions(
    fileId: string,
  ): Promise<SharedDatasetDrivePermission[]> {
    const permissions = await this.drive.listPermissions(
      fileId,
      await this.authorize(),
    );
    return permissions
      .filter(
        (permission) =>
          permission.type === "user" &&
          (permission.role === "reader" || permission.role === "writer"),
      )
      .map((permission) => ({
        permissionId: permission.permissionId,
        role: permission.role as "reader" | "writer",
        ...(permission.emailAddress
          ? { emailAddress: permission.emailAddress }
          : {}),
        inherited: permission.inherited ?? false,
      }));
  }

  async listDatasetHeads(): Promise<SharedDatasetHead[]> {
    const authorization = await this.authorize();
    const storage = await this.ensureStorage();
    const files = await this.listAll(authorization, {
      parentId: storage.appFolderId,
      appProperties: this.properties("dataset"),
    });
    return files.map((file) => ({
      datasetId: requiredProperty(
        file,
        SYNC_KIT_DATASET_ID_PROPERTY,
        "dataset",
      ),
      fileId: file.fileId,
      ...(file.modifiedTime ? { modifiedTime: file.modifiedTime } : {}),
      ...(file.version ? { version: file.version } : {}),
      ...(file.headRevisionId ? { headRevisionId: file.headRevisionId } : {}),
      ...(file.etag ? { etag: file.etag } : {}),
    }));
  }

  private async ensureStorageNow(): Promise<SharedBackupStorage> {
    const authorization = await this.authorize();
    const appFolderId =
      this.options.selectedAppFolderId ??
      (
        await ensureGoogleDriveSyncKitFolder(authorization, {
          appId: this.options.appId,
          ...(this.options.folderName
            ? { folderName: this.options.folderName }
            : {}),
          ...(this.options.parentFolderId
            ? { parentFolderId: this.options.parentFolderId }
            : {}),
          drive: this.drive,
        })
      ).appFolderId;
    const exchangeProperties = this.properties("exchange-folder");
    const existing = await this.drive.list(authorization, {
      parentId: appFolderId,
      appProperties: exchangeProperties,
    });
    const exchangesFolderId =
      existing.files.find((file) => file.name === "exchanges")?.fileId ??
      (await this.drive.createFolder("exchanges", authorization, {
        parentId: appFolderId,
        appProperties: exchangeProperties,
        writersCanShare: false,
      }));
    return { appFolderId, exchangesFolderId };
  }

  private async listAll(
    authorization: Authorization,
    options: Parameters<GoogleDriveFileStore["list"]>[1],
  ): Promise<DriveFileMetadata[]> {
    const files: DriveFileMetadata[] = [];
    let pageToken: string | undefined;
    do {
      const page = await this.drive.list(authorization, {
        ...options,
        ...(pageToken ? { pageToken } : {}),
      });
      files.push(...page.files);
      pageToken = page.nextPageToken;
    } while (pageToken);
    return files;
  }

  private properties(kind: string): Record<string, string> {
    return {
      [SYNC_KIT_APP_ID_PROPERTY]: this.options.appId,
      [SYNC_KIT_PROTOCOL_PROPERTY]: SHARING_PROTOCOL,
      [SYNC_KIT_KIND_PROPERTY]: kind,
    };
  }

  private assertManagedFile(file: DriveFileMetadata, kind: string): void {
    if (
      file.appProperties?.[SYNC_KIT_APP_ID_PROPERTY] !== this.options.appId ||
      file.appProperties?.[SYNC_KIT_PROTOCOL_PROPERTY] !== SHARING_PROTOCOL ||
      file.appProperties?.[SYNC_KIT_KIND_PROPERTY] !== kind
    ) {
      throw new SyncKitError(
        "compatibility",
        `The selected Drive file is not a managed ${kind} for this application.`,
      );
    }
  }

  private assertEnvelopeDataset(
    datasetId: string,
    envelope: SharedBackupEnvelopeV1,
  ): void {
    if (
      envelope.appId !== this.options.appId ||
      envelope.backupId !== datasetId
    ) {
      throw new SyncKitError(
        "compatibility",
        "The shared-backup envelope belongs to another dataset.",
      );
    }
  }

  private authorize(): Promise<Authorization> {
    return this.options.authorizationProvider.authorize();
  }
}

function requiredProperty(
  file: DriveFileMetadata,
  name: string,
  label: string,
): string {
  const value = file.appProperties?.[name];
  if (!value) {
    throw new SyncKitError(
      "compatibility",
      `A managed ${label} file is missing ${name}.`,
    );
  }
  return value;
}

function requireNonEmpty(value: string, name: string): void {
  if (!value.trim()) throw new TypeError(`${name} must not be empty.`);
}

// RFC 9110 ETags are quoted (optionally weak-prefixed); Drive change tokens
// like headRevisionId are not and must not be sent as If-Match.
function isHttpEtag(value: string): boolean {
  return value.startsWith('"') || value.startsWith("W/");
}
