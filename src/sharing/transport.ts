import type {
  SharedBackupEnvelopeV1,
  SharingInvitationV1,
  SharingPublicKeyResponseV1,
  SharingRole,
} from "./index.js";

export type SharedBackupStorage = {
  appFolderId: string;
  exchangesFolderId: string;
};

export type SharedDatasetFile = {
  datasetId: string;
  fileId: string;
  name: string;
  canEdit?: boolean;
};

export type VersionedSharedDataset = SharedDatasetFile & {
  envelope: SharedBackupEnvelopeV1;
  version: string;
};

export type SharedExchangeFile = {
  fileId: string;
  exchangeId: string;
  kind: "invitation" | "key-response";
  keyId?: string;
  createdTime?: string;
};

export type SharedKeyResponseFile = {
  fileId: string;
  response: SharingPublicKeyResponseV1;
  ownerPermissionId: string;
};

export type SharedDatasetPermission = {
  permissionId?: string;
  role: "reader" | "writer";
};

/**
 * Client-side transport required by the sharing controller. Implementations
 * may use Google Drive or another provider, but cannot depend on a trusted app
 * backend.
 */
export interface SharedBackupTransport {
  ensureStorage(): Promise<SharedBackupStorage>;
  listDatasets(): Promise<SharedDatasetFile[]>;
  readDataset(fileId: string): Promise<VersionedSharedDataset>;
  createDataset(
    datasetId: string,
    envelope: SharedBackupEnvelopeV1,
  ): Promise<VersionedSharedDataset>;
  writeDataset(
    current: VersionedSharedDataset,
    envelope: SharedBackupEnvelopeV1,
  ): Promise<VersionedSharedDataset>;
  grantExchangeAccess(
    emailAddress: string,
    options?: { sendNotificationEmail?: boolean; emailMessage?: string },
  ): Promise<{ drivePermissionId: string; appFolderId: string }>;
  createInvitation(invitation: SharingInvitationV1): Promise<string>;
  createKeyResponse(response: SharingPublicKeyResponseV1): Promise<string>;
  listExchanges(options?: {
    exchangeId?: string;
    kind?: SharedExchangeFile["kind"];
  }): Promise<SharedExchangeFile[]>;
  readInvitation(fileId: string): Promise<SharingInvitationV1>;
  readKeyResponse(
    fileId: string,
    expectedDrivePermissionId: string,
  ): Promise<SharedKeyResponseFile>;
  deleteExchange(fileId: string): Promise<void>;
  setDatasetPermission(
    fileId: string,
    emailAddress: string,
    role: Exclude<SharingRole, "owner" | "admin"> | "admin",
    options?: {
      existingDirectPermissionId?: string;
      inheritedReaderPermissionId?: string;
    },
  ): Promise<SharedDatasetPermission>;
  removeDatasetPermission(
    fileId: string,
    permissionId: string,
  ): Promise<void>;
}
