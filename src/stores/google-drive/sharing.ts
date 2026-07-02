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
  SharedDatasetFile,
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
    this.storagePromise ??= this.ensureStorageNow();
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
    const version = document.etag ?? metadata.etag;
    if (!version) {
      throw new SyncKitError(
        "state",
        "Google Drive did not expose an ETag for the dataset; a safe conditional write is unavailable.",
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
    return this.readDataset(fileId);
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
    await this.drive.write(
      current.fileId,
      JSON.stringify(envelope),
      authorization,
      {
        contentType: "application/json",
        ifMatch: current.version,
      },
    );
    return this.readDataset(current.fileId);
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
      inheritedReaderPermissionId?: string;
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
    if (driveRole === "reader" && options.inheritedReaderPermissionId) {
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
