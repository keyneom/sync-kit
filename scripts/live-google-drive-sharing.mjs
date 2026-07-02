import {
  GoogleDriveFileStore,
  SYNC_KIT_APP_ID_PROPERTY,
  SYNC_KIT_KIND_PROPERTY,
} from "../dist/stores/google-drive/index.js";
import { randomUUID } from "node:crypto";

const accessToken = process.env.SYNC_KIT_GOOGLE_ACCESS_TOKEN;
const recipientEmail = process.env.SYNC_KIT_GOOGLE_TEST_RECIPIENT;
if (!accessToken || !recipientEmail) {
  throw new Error(
    "Set SYNC_KIT_GOOGLE_ACCESS_TOKEN and SYNC_KIT_GOOGLE_TEST_RECIPIENT.",
  );
}

const authorization = { accessToken };
const drive = new GoogleDriveFileStore();
const suffix = randomUUID();
let folderId;
let fileId;
let folderPermissionId;
let filePermissionId;

try {
  folderId = await drive.createFolder(
    `Sync Kit Live Test ${suffix}`,
    authorization,
    {
      appProperties: {
        [SYNC_KIT_APP_ID_PROPERTY]: "sync-kit-live-test",
        [SYNC_KIT_KIND_PROPERTY]: "live-test-root",
      },
    },
  );
  fileId = await drive.create(
    `dataset-${suffix}.json`,
    '{"revision":1}',
    authorization,
    {
      parentId: folderId,
      contentType: "application/json",
      appProperties: {
        [SYNC_KIT_APP_ID_PROPERTY]: "sync-kit-live-test",
        [SYNC_KIT_KIND_PROPERTY]: "live-test-dataset",
      },
    },
  );
  const first = await drive.readTextVersioned(fileId, authorization);
  if (!first.etag) throw new Error("Drive did not expose a media ETag.");
  await drive.write(fileId, '{"revision":2}', authorization, {
    contentType: "application/json",
    ifMatch: first.etag,
  });
  let staleRejected = false;
  try {
    await drive.write(fileId, '{"revision":"stale"}', authorization, {
      contentType: "application/json",
      ifMatch: first.etag,
    });
  } catch (error) {
    staleRejected =
      error && typeof error === "object" && error.code === "conflict";
  }
  if (!staleRejected) {
    throw new Error("Drive accepted a stale conditional write.");
  }

  folderPermissionId = await drive.share(
    folderId,
    recipientEmail,
    "reader",
    authorization,
    { sendNotificationEmail: false },
  );
  filePermissionId = await drive.share(
    fileId,
    recipientEmail,
    "writer",
    authorization,
    { sendNotificationEmail: false },
  );
  if (folderPermissionId !== filePermissionId) {
    throw new Error("Drive permission IDs were not stable across files.");
  }
  const permissions = await drive.listPermissions(fileId, authorization);
  if (
    !permissions.some(
      (permission) =>
        permission.permissionId === filePermissionId &&
        permission.role === "writer",
    )
  ) {
    throw new Error("Drive did not apply the direct dataset writer role.");
  }
  console.log("Live Google Drive sharing validation passed.");
} finally {
  if (filePermissionId && fileId) {
    await drive.removePermission(
      fileId,
      filePermissionId,
      authorization,
    ).catch(() => undefined);
  }
  if (folderPermissionId && folderId) {
    await drive.removePermission(
      folderId,
      folderPermissionId,
      authorization,
    ).catch(() => undefined);
  }
  if (fileId) {
    await drive.delete(fileId, authorization).catch(() => undefined);
  }
  if (folderId) {
    await drive.delete(folderId, authorization).catch(() => undefined);
  }
}
