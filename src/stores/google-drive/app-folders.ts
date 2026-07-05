import type { Authorization } from "../../core/types.js";
import {
  GoogleDriveFileStore,
  SYNC_KIT_APP_ID_PROPERTY,
  SYNC_KIT_KIND_PROPERTY,
  type DriveFileMetadata,
} from "./index.js";

const DRIVE_FOLDER_MIME_TYPE = "application/vnd.google-apps.folder";

export type SyncKitAppFolder = {
  appFolderId: string;
  name: string;
  modifiedTime?: string;
};

export type ListAccessibleSyncKitAppFoldersOptions = {
  appId: string;
  authorization: Authorization;
  drive?: GoogleDriveFileStore;
};

/**
 * Lists sync-kit app-root folders the signed-in user can access for one
 * application ID. Useful when a recipient has several shared folders with
 * similar titles and needs to pick or disambiguate them in app UI.
 */
export async function listAccessibleSyncKitAppFolders(
  options: ListAccessibleSyncKitAppFoldersOptions,
): Promise<SyncKitAppFolder[]> {
  if (!options.appId.trim()) throw new TypeError("appId must not be empty.");
  const drive = options.drive ?? new GoogleDriveFileStore();
  const folders: SyncKitAppFolder[] = [];
  let pageToken: string | undefined;
  do {
    const page = await drive.list(options.authorization, {
      appProperties: {
        [SYNC_KIT_APP_ID_PROPERTY]: options.appId,
        [SYNC_KIT_KIND_PROPERTY]: "app-root",
      },
      ...(pageToken ? { pageToken } : {}),
    });
    for (const file of page.files) {
      if (isAppRootFolder(file)) {
        folders.push({
          appFolderId: file.fileId,
          name: file.name,
          ...(file.modifiedTime ? { modifiedTime: file.modifiedTime } : {}),
        });
      }
    }
    pageToken = page.nextPageToken;
  } while (pageToken);
  return folders.sort((left, right) => left.name.localeCompare(right.name));
}

function isAppRootFolder(file: DriveFileMetadata): boolean {
  return file.mimeType === DRIVE_FOLDER_MIME_TYPE;
}
