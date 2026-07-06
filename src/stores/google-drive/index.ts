import type {
  Authorization,
  CloudStore,
  StoredEnvelope,
} from "../../core/types.js";
import { SyncKitError } from "../../core/errors.js";

const DRIVE_API = "https://www.googleapis.com/drive/v3/files";
const DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3/files";
const DRIVE_V2_API = "https://www.googleapis.com/drive/v2/files";
const DRIVE_V2_UPLOAD_API =
  "https://www.googleapis.com/upload/drive/v2/files";
const DRIVE_FOLDER_MIME_TYPE = "application/vnd.google-apps.folder";

export const SYNC_KIT_APP_ID_PROPERTY = "sync-kit-app-id";
export const SYNC_KIT_KIND_PROPERTY = "sync-kit-kind";
export const SYNC_KIT_DATASET_ID_PROPERTY = "sync-kit-dataset-id";
export const SYNC_KIT_PROTOCOL_PROPERTY = "sync-kit-protocol";

export function defaultSyncKitAppFolderName(appId: string): string {
  return `Sync Kit - ${appId}`;
}

export type DriveObject = {
  fileId: string;
  name: string;
  modifiedTime?: string;
};

export type GoogleDriveStoreOptions = {
  fetch?: typeof fetch;
  randomUUID?: () => string;
  onUnauthorized?: () => void;
  resourceKeys?: Record<string, string>;
};

export type GoogleDriveAppDataOptions = GoogleDriveStoreOptions;

export type DriveContent =
  | string
  | Blob
  | ArrayBuffer
  | Uint8Array<ArrayBuffer>;

export class GoogleDriveAppDataStore {
  constructor(private readonly options: GoogleDriveAppDataOptions = {}) {}

  async find(
    name: string,
    authorization: Authorization,
  ): Promise<DriveObject | null> {
    const params = new URLSearchParams({
      spaces: "appDataFolder",
      q: `name = '${escapeDriveQuery(name)}' and trashed = false`,
      fields: "files(id,name,modifiedTime)",
      pageSize: "1",
    });
    const response = await this.request(
      `${DRIVE_API}?${params}`,
      authorization,
    );
    const value = (await response.json()) as {
      files?: { id: string; name?: string; modifiedTime?: string }[];
    };
    const file = value.files?.[0];
    return file
        ? {
            fileId: file.id,
            name: file.name ?? name,
            ...(file.modifiedTime === undefined
              ? {}
              : { modifiedTime: file.modifiedTime }),
          }
      : null;
  }

  async readText(
    fileId: string,
    authorization: Authorization,
  ): Promise<string> {
    const response = await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}?alt=media`,
      authorization,
    );
    return response.text();
  }

  async readBytes(
    fileId: string,
    authorization: Authorization,
  ): Promise<Uint8Array> {
    const response = await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}?alt=media`,
      authorization,
    );
    return new Uint8Array(await response.arrayBuffer());
  }

  async write(
    name: string,
    content: DriveContent,
    authorization: Authorization,
    options: { existingId?: string; contentType?: string } = {},
  ): Promise<string> {
    const contentType = options.contentType ?? "application/octet-stream";
    if (options.existingId) {
      await this.request(
        `${DRIVE_UPLOAD_API}/${encodeURIComponent(options.existingId)}?uploadType=media&fields=id`,
        authorization,
        {
          method: "PATCH",
          headers: { "Content-Type": contentType },
          body: content,
        },
      );
      return options.existingId;
    }
    const boundary = `sync-kit-${this.randomUUID()}`;
    const body = new Blob([
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n`,
      JSON.stringify({ name, parents: ["appDataFolder"] }),
      `\r\n--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`,
      content,
      `\r\n--${boundary}--`,
    ]);
    const response = await this.request(
      `${DRIVE_UPLOAD_API}?uploadType=multipart&fields=id`,
      authorization,
      {
        method: "POST",
        headers: { "Content-Type": `multipart/related; boundary=${boundary}` },
        body,
      },
    );
    const created = (await response.json()) as { id?: string };
    if (!created.id) {
      throw new SyncKitError(
        "provider",
        "Google Drive did not return a file ID.",
      );
    }
    return created.id;
  }

  async delete(fileId: string, authorization: Authorization): Promise<void> {
    await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}`,
      authorization,
      { method: "DELETE" },
    );
  }

  private async request(
    url: string,
    authorization: Authorization,
    init: RequestInit = {},
  ): Promise<Response> {
    const fetchImplementation = this.options.fetch ?? globalThis.fetch;
    if (!fetchImplementation) {
      throw new SyncKitError(
        "configuration",
        "A Fetch API implementation is required.",
      );
    }
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${authorization.accessToken}`);
    const resourceKeys = Object.entries(this.options.resourceKeys ?? {});
    if (resourceKeys.length > 0) {
      headers.set(
        "X-Goog-Drive-Resource-Keys",
        resourceKeys.map(([fileId, key]) => `${fileId}/${key}`).join(","),
      );
    }
    const response = await fetchImplementation(url, {
      ...init,
      headers,
    });
    if (!response.ok) {
      if (response.status === 401) this.options.onUnauthorized?.();
      const detail = (await response.text()).slice(0, 400);
      throw new SyncKitError(
        response.status === 404 ? "not-found" : "provider",
        `Google Drive request failed (${response.status}). ${detail}`,
        { status: response.status },
      );
    }
    return response;
  }

  private randomUUID(): string {
    const implementation =
      this.options.randomUUID ??
      (typeof crypto === "undefined"
        ? undefined
        : crypto.randomUUID.bind(crypto));
    if (!implementation) {
      throw new SyncKitError(
        "configuration",
        "Secure UUID generation is unavailable.",
      );
    }
    return implementation();
  }
}

export type GoogleDriveSnapshotStoreOptions<E> = {
  appId: string;
  filename: string;
  parse(value: string): E;
  serialize?(value: E): string;
  drive?: GoogleDriveAppDataStore;
};

export class GoogleDriveSnapshotStore<E>
  implements CloudStore<E, Authorization>
{
  private readonly drive: GoogleDriveAppDataStore;

  constructor(private readonly options: GoogleDriveSnapshotStoreOptions<E>) {
    this.drive = options.drive ?? new GoogleDriveAppDataStore();
  }

  async find(
    appId: string,
    authorization: Authorization,
  ): Promise<StoredEnvelope<E> | null> {
    this.assertAppId(appId);
    const found = await this.drive.find(this.options.filename, authorization);
    if (!found) return null;
    return {
      fileId: found.fileId,
      envelope: this.options.parse(
        await this.drive.readText(found.fileId, authorization),
      ),
    };
  }

  write(
    appId: string,
    envelope: E,
    authorization: Authorization,
    existingId?: string,
  ): Promise<string> {
    this.assertAppId(appId);
    return this.drive.write(
      this.options.filename,
      this.options.serialize?.(envelope) ?? JSON.stringify(envelope),
      authorization,
      {
        ...(existingId === undefined ? {} : { existingId }),
        contentType: "application/json",
      },
    );
  }

  async delete(
    appId: string,
    fileId: string,
    authorization: Authorization,
  ): Promise<void> {
    this.assertAppId(appId);
    await this.drive.delete(fileId, authorization);
  }

  private assertAppId(appId: string): void {
    if (appId !== this.options.appId) {
      throw new SyncKitError(
        "compatibility",
        `The ${this.options.appId} store rejected app ID ${appId}.`,
      );
    }
  }
}

export type DriveFileRole = "reader" | "writer";

export type DriveFileMetadata = DriveObject & {
  mimeType?: string;
  parents?: string[];
  appProperties?: Record<string, string>;
  createdTime?: string;
  version?: string;
  headRevisionId?: string;
  etag?: string;
  inheritedPermissionsDisabled?: boolean;
  owners?: DriveUser[];
  sharingUser?: DriveUser;
  lastModifyingUser?: DriveUser;
  capabilities?: {
    canEdit?: boolean;
    canShare?: boolean;
    canDelete?: boolean;
    canListChildren?: boolean;
    canDisableInheritedPermissions?: boolean;
    canEnableInheritedPermissions?: boolean;
  };
};

export type DriveUser = {
  displayName?: string;
  permissionId?: string;
  emailAddress?: string;
  me?: boolean;
};

export type DriveFileProvenanceExpectation = {
  permissionId?: string;
  emailAddress?: string;
  sharingUserPermissionId?: string;
};

/**
 * Confirms that a My Drive exchange response is still owned and last modified
 * by the expected Google account. The response content still needs its own
 * cryptographic proof.
 */
export function assertDriveFileProvenance(
  file: DriveFileMetadata,
  expected: DriveFileProvenanceExpectation,
): void {
  if (!expected.permissionId && !expected.emailAddress) {
    throw new TypeError(
      "Expected permissionId or emailAddress is required.",
    );
  }
  if (file.owners?.length !== 1) {
    throw new SyncKitError(
      "authorization",
      "The exchange response is not a singly owned My Drive file.",
    );
  }
  const owner = file.owners[0];
  if (!owner || !driveUserMatches(owner, expected)) {
    throw new SyncKitError(
      "authorization",
      "The exchange response is not owned by the expected Google account.",
    );
  }
  if (
    !file.lastModifyingUser ||
    !driveUserMatches(file.lastModifyingUser, expected)
  ) {
    throw new SyncKitError(
      "authorization",
      "The exchange response was modified by another Google account.",
    );
  }
  if (
    expected.sharingUserPermissionId &&
    file.sharingUser?.permissionId !== expected.sharingUserPermissionId
  ) {
    throw new SyncKitError(
      "authorization",
      "The exchange response has unexpected sharing provenance.",
    );
  }
}

export type DriveFileList = {
  files: DriveFileMetadata[];
  nextPageToken?: string;
};

export type GoogleDriveFileCreateOptions = {
  parentId?: string;
  contentType?: string;
  appProperties?: Record<string, string>;
  writersCanShare?: boolean;
};

export type DriveFileContent = {
  content: string;
  etag?: string;
};

export type GoogleDriveFileWriteOptions = {
  contentType?: string;
  ifMatch?: string;
};

export type DriveFileWriteResult = {
  fileId: string;
  etag?: string;
};

export type DriveV2WriteHead = {
  etag: string;
  headRevisionId?: string;
};

export type DriveV2WriteResult = {
  fileId: string;
  etag: string;
  headRevisionId?: string;
};

/** Thrown when Drive v2 endpoints are gone; callers may fall back to v3. */
export class DriveV2UnavailableError extends SyncKitError {
  constructor(options: ErrorOptions = {}) {
    super("not-found", "Google Drive v2 API is unavailable.", options);
  }
}

export function isDriveV2UnavailableError(
  value: unknown,
): value is DriveV2UnavailableError {
  return value instanceof DriveV2UnavailableError;
}

export type DrivePermission = {
  permissionId: string;
  type: "user" | "group" | "domain" | "anyone";
  role: string;
  emailAddress?: string;
  displayName?: string;
  inherited?: boolean;
};

/**
 * A per-file Google Drive adapter for user-visible and shareable files.
 *
 * Use it with the non-sensitive `drive.file` scope and a Picker/Open-with flow.
 * It intentionally does not search or request access to the user's whole Drive.
 */
export class GoogleDriveFileStore {
  constructor(private readonly options: GoogleDriveStoreOptions = {}) {}

  async get(
    fileId: string,
    authorization: Authorization,
  ): Promise<DriveFileMetadata> {
    const params = new URLSearchParams({
      fields:
        "id,name,mimeType,createdTime,modifiedTime,version,headRevisionId,parents,appProperties,inheritedPermissionsDisabled,owners(displayName,permissionId,emailAddress,me),sharingUser(displayName,permissionId,emailAddress,me),lastModifyingUser(displayName,permissionId,emailAddress,me),capabilities(canEdit,canShare,canDelete,canListChildren,canDisableInheritedPermissions,canEnableInheritedPermissions)",
      supportsAllDrives: "true",
    });
    const response = await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}?${params}`,
      authorization,
    );
    return driveFileMetadata(
      (await response.json()) as GoogleDriveFileApiMetadata,
      response.headers.get("ETag") ?? undefined,
    );
  }

  async list(
    authorization: Authorization,
    options: {
      parentId?: string;
      appProperties?: Record<string, string>;
      pageToken?: string;
      pageSize?: number;
    } = {},
  ): Promise<DriveFileList> {
    const clauses = ["trashed = false"];
    if (options.parentId) {
      clauses.push(`'${escapeDriveQuery(options.parentId)}' in parents`);
    }
    for (const [key, value] of Object.entries(options.appProperties ?? {})) {
      clauses.push(
        `appProperties has { key='${escapeDriveQuery(key)}' and value='${escapeDriveQuery(value)}' }`,
      );
    }
    const params = new URLSearchParams({
      spaces: "drive",
      corpora: "user",
      q: clauses.join(" and "),
      fields:
        "nextPageToken,files(id,name,mimeType,modifiedTime,version,headRevisionId,parents,appProperties,capabilities(canEdit,canShare,canDelete))",
      pageSize: String(options.pageSize ?? 100),
      supportsAllDrives: "true",
      includeItemsFromAllDrives: "true",
    });
    if (options.pageToken) params.set("pageToken", options.pageToken);
    const response = await this.request(
      `${DRIVE_API}?${params}`,
      authorization,
    );
    const body = (await response.json()) as {
      files?: GoogleDriveFileApiMetadata[];
      nextPageToken?: string;
    };
    return {
      files: (body.files ?? []).map((file) => driveFileMetadata(file)),
      ...(body.nextPageToken ? { nextPageToken: body.nextPageToken } : {}),
    };
  }

  async readText(
    fileId: string,
    authorization: Authorization,
  ): Promise<string> {
    return (await this.readTextVersioned(fileId, authorization)).content;
  }

  async readTextVersioned(
    fileId: string,
    authorization: Authorization,
  ): Promise<DriveFileContent> {
    const response = await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}?alt=media&supportsAllDrives=true`,
      authorization,
    );
    const content = await response.text();
    const etag = response.headers.get("ETag");
    return {
      content,
      ...(etag ? { etag } : {}),
    };
  }

  async readBytes(
    fileId: string,
    authorization: Authorization,
  ): Promise<Uint8Array> {
    const response = await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}?alt=media&supportsAllDrives=true`,
      authorization,
    );
    return new Uint8Array(await response.arrayBuffer());
  }

  async create(
    name: string,
    content: DriveContent,
    authorization: Authorization,
    options: GoogleDriveFileCreateOptions = {},
  ): Promise<string> {
    const boundary = `sync-kit-${this.randomUUID()}`;
    const contentType = options.contentType ?? "application/octet-stream";
    const metadata = {
      name,
      ...(options.parentId ? { parents: [options.parentId] } : {}),
      ...(options.appProperties
        ? { appProperties: options.appProperties }
        : {}),
      writersCanShare: options.writersCanShare ?? false,
    };
    const body = new Blob([
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n`,
      JSON.stringify(metadata),
      `\r\n--${boundary}\r\nContent-Type: ${contentType}\r\n\r\n`,
      content,
      `\r\n--${boundary}--`,
    ]);
    const response = await this.request(
      `${DRIVE_UPLOAD_API}?uploadType=multipart&fields=id&supportsAllDrives=true`,
      authorization,
      {
        method: "POST",
        headers: { "Content-Type": `multipart/related; boundary=${boundary}` },
        body,
      },
    );
    return responseFileId(response);
  }

  async createFolder(
    name: string,
    authorization: Authorization,
    options: Omit<GoogleDriveFileCreateOptions, "contentType"> = {},
  ): Promise<string> {
    const response = await this.request(
      `${DRIVE_API}?fields=id&supportsAllDrives=true`,
      authorization,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          mimeType: DRIVE_FOLDER_MIME_TYPE,
          ...(options.parentId ? { parents: [options.parentId] } : {}),
          ...(options.appProperties
            ? { appProperties: options.appProperties }
            : {}),
          writersCanShare: options.writersCanShare ?? false,
        }),
      },
    );
    return responseFileId(response);
  }

  async write(
    fileId: string,
    content: DriveContent,
    authorization: Authorization,
    options: string | GoogleDriveFileWriteOptions = {},
  ): Promise<DriveFileWriteResult> {
    const normalized =
      typeof options === "string" ? { contentType: options } : options;
    const headers = new Headers({
      "Content-Type": normalized.contentType ?? "application/octet-stream",
    });
    if (normalized.ifMatch) headers.set("If-Match", normalized.ifMatch);
    const response = await this.request(
      `${DRIVE_UPLOAD_API}/${encodeURIComponent(fileId)}?uploadType=media&fields=id&supportsAllDrives=true`,
      authorization,
      {
        method: "PATCH",
        headers,
        body: content,
      },
    );
    const etag = response.headers.get("ETag");
    return {
      fileId,
      ...(etag ? { etag } : {}),
    };
  }

  async getV2WriteHead(
    fileId: string,
    authorization: Authorization,
  ): Promise<DriveV2WriteHead> {
    try {
      const response = await this.request(
        `${DRIVE_V2_API}/${encodeURIComponent(fileId)}?fields=etag,headRevisionId`,
        authorization,
      );
      const body = (await response.json()) as {
        etag?: string;
        headRevisionId?: string;
      };
      const etag = body.etag;
      if (!etag) {
        throw new SyncKitError(
          "provider",
          "Google Drive v2 metadata did not include an etag.",
        );
      }
      return {
        etag,
        ...(body.headRevisionId ? { headRevisionId: body.headRevisionId } : {}),
      };
    } catch (error) {
      if (isDriveV2EndpointUnavailable(error)) {
        throw new DriveV2UnavailableError({ cause: error });
      }
      throw error;
    }
  }

  async writeV2Media(
    fileId: string,
    content: DriveContent,
    authorization: Authorization,
    options: { ifMatch: string; contentType?: string },
  ): Promise<DriveV2WriteResult> {
    try {
      const headers = new Headers({
        "Content-Type": options.contentType ?? "application/octet-stream",
        "If-Match": options.ifMatch,
      });
      const response = await this.request(
        `${DRIVE_V2_UPLOAD_API}/${encodeURIComponent(fileId)}?uploadType=media&fields=etag,headRevisionId`,
        authorization,
        {
          method: "PUT",
          headers,
          body: content,
        },
      );
      const body = (await response.json()) as {
        etag?: string;
        headRevisionId?: string;
      };
      const etag = body.etag;
      if (!etag) {
        throw new SyncKitError(
          "provider",
          "Google Drive v2 upload did not return an etag.",
        );
      }
      return {
        fileId,
        etag,
        ...(body.headRevisionId ? { headRevisionId: body.headRevisionId } : {}),
      };
    } catch (error) {
      if (isDriveV2EndpointUnavailable(error)) {
        throw new DriveV2UnavailableError({ cause: error });
      }
      throw error;
    }
  }

  async share(
    fileId: string,
    emailAddress: string,
    role: DriveFileRole,
    authorization: Authorization,
    options: {
      sendNotificationEmail?: boolean;
      emailMessage?: string;
    } = {},
  ): Promise<string> {
    const params = new URLSearchParams({
      fields: "id",
      supportsAllDrives: "true",
      sendNotificationEmail: String(options.sendNotificationEmail ?? true),
    });
    if (options.emailMessage) {
      params.set("emailMessage", options.emailMessage);
    }
    const response = await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}/permissions?${params}`,
      authorization,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "user", role, emailAddress }),
      },
    );
    return responseFileId(response, "permission");
  }

  async removePermission(
    fileId: string,
    permissionId: string,
    authorization: Authorization,
  ): Promise<void> {
    await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}/permissions/${encodeURIComponent(permissionId)}?supportsAllDrives=true`,
      authorization,
      { method: "DELETE" },
    );
  }

  async listPermissions(
    fileId: string,
    authorization: Authorization,
  ): Promise<DrivePermission[]> {
    const params = new URLSearchParams({
      fields:
        "permissions(id,type,role,emailAddress,displayName,permissionDetails(inherited))",
      supportsAllDrives: "true",
    });
    const response = await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}/permissions?${params}`,
      authorization,
    );
    const body = (await response.json()) as {
      permissions?: GoogleDrivePermissionApi[];
    };
    return (body.permissions ?? []).map(drivePermission);
  }

  async updatePermission(
    fileId: string,
    permissionId: string,
    role: DriveFileRole,
    authorization: Authorization,
  ): Promise<void> {
    await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}/permissions/${encodeURIComponent(permissionId)}?supportsAllDrives=true`,
      authorization,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role }),
      },
    );
  }

  async setFolderLimitedAccess(
    folderId: string,
    enabled: boolean,
    authorization: Authorization,
  ): Promise<void> {
    await this.request(
      `${DRIVE_API}/${encodeURIComponent(folderId)}?supportsAllDrives=true`,
      authorization,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ inheritedPermissionsDisabled: enabled }),
      },
    );
  }

  async delete(fileId: string, authorization: Authorization): Promise<void> {
    await this.request(
      `${DRIVE_API}/${encodeURIComponent(fileId)}?supportsAllDrives=true`,
      authorization,
      { method: "DELETE" },
    );
  }

  private async request(
    url: string,
    authorization: Authorization,
    init: RequestInit = {},
  ): Promise<Response> {
    const fetchImplementation = this.options.fetch ?? globalThis.fetch;
    if (!fetchImplementation) {
      throw new SyncKitError(
        "configuration",
        "A Fetch API implementation is required.",
      );
    }
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${authorization.accessToken}`);
    const resourceKeys = Object.entries(this.options.resourceKeys ?? {});
    if (resourceKeys.length > 0) {
      headers.set(
        "X-Goog-Drive-Resource-Keys",
        resourceKeys.map(([fileId, key]) => `${fileId}/${key}`).join(","),
      );
    }
    const response = await fetchImplementation(url, { ...init, headers });
    if (!response.ok) {
      if (response.status === 401) this.options.onUnauthorized?.();
      const detail = (await response.text()).slice(0, 400);
      throw new SyncKitError(
        response.status === 409 || response.status === 412
          ? "conflict"
          : response.status === 404
            ? "not-found"
            : "provider",
        `Google Drive request failed (${response.status}). ${detail}`,
        { status: response.status },
      );
    }
    return response;
  }

  private randomUUID(): string {
    const implementation =
      this.options.randomUUID ??
      (typeof crypto === "undefined"
        ? undefined
        : crypto.randomUUID.bind(crypto));
    if (!implementation) {
      throw new SyncKitError(
        "configuration",
        "Secure UUID generation is unavailable.",
      );
    }
    return implementation();
  }
}

function isDriveV2EndpointUnavailable(error: unknown): boolean {
  return (
    error instanceof SyncKitError &&
    (error.status === 404 || error.status === 410)
  );
}

export type GoogleDriveSyncKitFolderOptions = {
  appId: string;
  folderName?: string;
  parentFolderId?: string;
  drive?: GoogleDriveFileStore;
};

export type GoogleDriveSyncKitFolder = {
  appFolderId: string;
};

/**
 * Finds or creates a private, app-specific normal-Drive folder. A consumer can
 * explicitly supply a selected parent, but no common cross-app root is needed.
 */
export async function ensureGoogleDriveSyncKitFolder(
  authorization: Authorization,
  options: GoogleDriveSyncKitFolderOptions,
): Promise<GoogleDriveSyncKitFolder> {
  if (!options.appId.trim()) throw new TypeError("appId must not be empty.");
  const drive = options.drive ?? new GoogleDriveFileStore();
  const folderName =
    options.folderName ?? defaultSyncKitAppFolderName(options.appId);
  const appProperties = {
    [SYNC_KIT_KIND_PROPERTY]: "app-root",
    [SYNC_KIT_APP_ID_PROPERTY]: options.appId,
  };
  const appFolderId =
    (await findFolder(
      drive,
      authorization,
      folderName,
      options.parentFolderId,
      appProperties,
    )) ??
    (await drive.createFolder(folderName, authorization, {
      ...(options.parentFolderId
        ? { parentId: options.parentFolderId }
        : {}),
      appProperties,
    }));
  return { appFolderId };
}

export type GoogleDriveFileSnapshotStoreOptions<E> =
  GoogleDriveSyncKitFolderOptions & {
    filename: string;
    parse(value: string): E;
    serialize?(value: E): string;
  };

/**
 * Snapshot CloudStore backed by a user-visible normal Drive folder.
 * This is the default storage model for new integrations; legacy consumers can
 * continue using GoogleDriveSnapshotStore with appDataFolder.
 */
export class GoogleDriveFileSnapshotStore<E>
  implements CloudStore<E, Authorization>
{
  private readonly drive: GoogleDriveFileStore;
  private folderPromise: Promise<GoogleDriveSyncKitFolder> | null = null;

  constructor(
    private readonly options: GoogleDriveFileSnapshotStoreOptions<E>,
  ) {
    this.drive = options.drive ?? new GoogleDriveFileStore();
  }

  async find(
    appId: string,
    authorization: Authorization,
  ): Promise<StoredEnvelope<E> | null> {
    this.assertAppId(appId);
    const folders = await this.folders(authorization);
    const listed = await this.drive.list(authorization, {
      parentId: folders.appFolderId,
      appProperties: this.fileProperties(),
    });
    const file = listed.files.find(
      (candidate) => candidate.name === this.options.filename,
    );
    if (!file) return null;
    return {
      fileId: file.fileId,
      envelope: this.options.parse(
        await this.drive.readText(file.fileId, authorization),
      ),
    };
  }

  async write(
    appId: string,
    envelope: E,
    authorization: Authorization,
    existingId?: string,
  ): Promise<string> {
    this.assertAppId(appId);
    const content =
      this.options.serialize?.(envelope) ?? JSON.stringify(envelope);
    if (existingId) {
      await this.drive.write(
        existingId,
        content,
        authorization,
        { contentType: "application/json" },
      );
      return existingId;
    }
    const folders = await this.folders(authorization);
    return this.drive.create(
      this.options.filename,
      content,
      authorization,
      {
        parentId: folders.appFolderId,
        contentType: "application/json",
        appProperties: this.fileProperties(),
      },
    );
  }

  async delete(
    appId: string,
    fileId: string,
    authorization: Authorization,
  ): Promise<void> {
    this.assertAppId(appId);
    await this.drive.delete(fileId, authorization);
  }

  private folders(
    authorization: Authorization,
  ): Promise<GoogleDriveSyncKitFolder> {
    this.folderPromise ??= ensureGoogleDriveSyncKitFolder(authorization, {
      appId: this.options.appId,
      ...(this.options.folderName
        ? { folderName: this.options.folderName }
        : {}),
      ...(this.options.parentFolderId
        ? { parentFolderId: this.options.parentFolderId }
        : {}),
      drive: this.drive,
    }).catch((error: unknown) => {
      this.folderPromise = null;
      throw error;
    });
    return this.folderPromise;
  }

  private fileProperties(): Record<string, string> {
    return {
      [SYNC_KIT_KIND_PROPERTY]: "snapshot",
      [SYNC_KIT_APP_ID_PROPERTY]: this.options.appId,
    };
  }

  private assertAppId(appId: string): void {
    if (appId !== this.options.appId) {
      throw new SyncKitError(
        "compatibility",
        `The ${this.options.appId} file store rejected app ID ${appId}.`,
      );
    }
  }
}

type GoogleDriveFileApiMetadata = {
  id?: string;
  name?: string;
  mimeType?: string;
  modifiedTime?: string;
  parents?: string[];
  appProperties?: Record<string, string>;
  createdTime?: string;
  version?: string;
  headRevisionId?: string;
  inheritedPermissionsDisabled?: boolean;
  owners?: DriveUser[];
  sharingUser?: DriveUser;
  lastModifyingUser?: DriveUser;
  capabilities?: DriveFileMetadata["capabilities"];
};

function driveFileMetadata(
  value: GoogleDriveFileApiMetadata,
  etag?: string,
): DriveFileMetadata {
  if (!value.id || !value.name) {
    throw new SyncKitError(
      "provider",
      "Google Drive returned incomplete file metadata.",
    );
  }
  return {
    fileId: value.id,
    name: value.name,
    ...(value.mimeType ? { mimeType: value.mimeType } : {}),
    ...(value.modifiedTime ? { modifiedTime: value.modifiedTime } : {}),
    ...(value.createdTime ? { createdTime: value.createdTime } : {}),
    ...(value.version ? { version: value.version } : {}),
    ...(value.headRevisionId ? { headRevisionId: value.headRevisionId } : {}),
    ...(etag ? { etag } : {}),
    ...(value.inheritedPermissionsDisabled === undefined
      ? {}
      : {
          inheritedPermissionsDisabled: value.inheritedPermissionsDisabled,
        }),
    ...(value.parents ? { parents: value.parents } : {}),
    ...(value.appProperties ? { appProperties: value.appProperties } : {}),
    ...(value.owners ? { owners: value.owners } : {}),
    ...(value.sharingUser ? { sharingUser: value.sharingUser } : {}),
    ...(value.lastModifyingUser
      ? { lastModifyingUser: value.lastModifyingUser }
      : {}),
    ...(value.capabilities ? { capabilities: value.capabilities } : {}),
  };
}

type GoogleDrivePermissionApi = {
  id?: string;
  type?: "user" | "group" | "domain" | "anyone";
  role?: string;
  emailAddress?: string;
  displayName?: string;
  permissionDetails?: { inherited?: boolean }[];
};

function drivePermission(value: GoogleDrivePermissionApi): DrivePermission {
  if (!value.id || !value.type || !value.role) {
    throw new SyncKitError(
      "provider",
      "Google Drive returned incomplete permission metadata.",
    );
  }
  return {
    permissionId: value.id,
    type: value.type,
    role: value.role,
    ...(value.emailAddress ? { emailAddress: value.emailAddress } : {}),
    ...(value.displayName ? { displayName: value.displayName } : {}),
    ...(value.permissionDetails?.some((detail) => detail.inherited)
      ? { inherited: true }
      : {}),
  };
}

async function findFolder(
  drive: GoogleDriveFileStore,
  authorization: Authorization,
  name: string,
  parentId: string | undefined,
  appProperties: Record<string, string>,
): Promise<string | null> {
  const listed = await drive.list(authorization, {
    ...(parentId ? { parentId } : {}),
    appProperties,
  });
  return (
    listed.files.find(
      (candidate) =>
        candidate.name === name && candidate.mimeType === DRIVE_FOLDER_MIME_TYPE,
    )?.fileId ?? null
  );
}

async function responseFileId(
  response: Response,
  kind = "file",
): Promise<string> {
  const body = (await response.json()) as { id?: string };
  if (!body.id) {
    throw new SyncKitError(
      "provider",
      `Google Drive did not return a ${kind} ID.`,
    );
  }
  return body.id;
}

function driveUserMatches(
  user: DriveUser,
  expected: DriveFileProvenanceExpectation,
): boolean {
  if (expected.permissionId) {
    return user.permissionId === expected.permissionId;
  }
  return (
    user.emailAddress?.toLocaleLowerCase() ===
    expected.emailAddress?.toLocaleLowerCase()
  );
}

function escapeDriveQuery(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("'", "\\'");
}

export {
  buildSyncKitFolderName,
  sanitizeDriveFolderName,
  type SyncKitFolderNameInput,
} from "./folder-name.js";
export {
  listAccessibleSyncKitAppFolders,
  type ListAccessibleSyncKitAppFoldersOptions,
  type SyncKitAppFolder,
} from "./app-folders.js";
