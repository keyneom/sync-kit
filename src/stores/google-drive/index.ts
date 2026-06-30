import type {
  Authorization,
  CloudStore,
  StoredEnvelope,
} from "../../core/types.js";
import { SyncKitError } from "../../core/errors.js";

const DRIVE_API = "https://www.googleapis.com/drive/v3/files";
const DRIVE_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3/files";

export type DriveObject = {
  fileId: string;
  name: string;
  modifiedTime?: string;
};

export type GoogleDriveAppDataOptions = {
  fetch?: typeof fetch;
  randomUUID?: () => string;
  onUnauthorized?: () => void;
};

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

function escapeDriveQuery(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("'", "\\'");
}
