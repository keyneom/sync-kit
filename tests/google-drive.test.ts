import { describe, expect, it, vi } from "vitest";
import {
  assertDriveFileProvenance,
  GoogleDriveAppDataStore,
  GoogleDriveFileStore,
  GoogleDriveFileSnapshotStore,
  GoogleDriveSnapshotStore,
} from "../src/stores/google-drive/index.js";
import { GoogleDriveSharedBackupTransport } from "../src/stores/google-drive/sharing.js";

const authorization = { accessToken: "token" };

describe("Google Drive appDataFolder", () => {
  it("uses an exact app-specific filename and parses the selected snapshot", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json({
          files: [{ id: "file", name: "easybc-sync-v1.json" }],
        }),
      )
      .mockResolvedValueOnce(
        new Response('{"schemaVersion":1,"ciphertext":"fixture"}'),
      );
    const drive = new GoogleDriveAppDataStore({ fetch });
    const store = new GoogleDriveSnapshotStore({
      appId: "easy-bc",
      filename: "easybc-sync-v1.json",
      parse: JSON.parse,
      drive,
    });

    await expect(store.find("easy-bc", authorization)).resolves.toEqual({
      fileId: "file",
      envelope: { schemaVersion: 1, ciphertext: "fixture" },
    });
    const query = new URL(fetch.mock.calls[0]?.[0] as string).searchParams.get(
      "q",
    );
    expect(query).toBe(
      "name = 'easybc-sync-v1.json' and trashed = false",
    );
    const headers = fetch.mock.calls[0]?.[1]?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer token");
  });

  it("rejects cross-app access before touching Drive", async () => {
    const fetch = vi.fn();
    const store = new GoogleDriveSnapshotStore({
      appId: "family-chores",
      filename: "family-chores-sync-v1.json",
      parse: JSON.parse,
      drive: new GoogleDriveAppDataStore({ fetch }),
    });
    await expect(store.find("easy-bc", authorization)).rejects.toMatchObject({
      code: "compatibility",
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("supports binary objects for native manifests and attachment blobs", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ id: "created" }))
      .mockResolvedValueOnce(new Response(Uint8Array.of(1, 2, 3)));
    const drive = new GoogleDriveAppDataStore({
      fetch,
      randomUUID: () => "boundary",
    });

    await expect(
      drive.write(
        "keynote/blobs/hash",
        Uint8Array.of(1, 2, 3),
        authorization,
      ),
    ).resolves.toBe("created");
    await expect(drive.readBytes("created", authorization)).resolves.toEqual(
      Uint8Array.of(1, 2, 3),
    );
    expect(fetch.mock.calls[0]?.[0]).toContain("uploadType=multipart");
  });

  it("invalidates authorization on HTTP 401 and reports provider status", async () => {
    const onUnauthorized = vi.fn();
    const drive = new GoogleDriveAppDataStore({
      fetch: vi.fn().mockResolvedValue(
        new Response("expired", { status: 401 }),
      ),
      onUnauthorized,
    });
    await expect(drive.find("snapshot.json", authorization)).rejects.toMatchObject({
      code: "provider",
      status: 401,
    });
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });
});

describe("Google Drive per-file sharing", () => {
  it("creates the managed app/exchange hierarchy and grants narrow access", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ files: [] }))
      .mockResolvedValueOnce(Response.json({ id: "app-folder" }))
      .mockResolvedValueOnce(Response.json({ files: [] }))
      .mockResolvedValueOnce(Response.json({ id: "exchanges-folder" }))
      .mockResolvedValueOnce(Response.json({ id: "recipient-permission" }))
      .mockResolvedValueOnce(Response.json({ id: "recipient-permission" }));
    const drive = new GoogleDriveFileStore({
      fetch,
      randomUUID: () => "boundary",
    });
    const transport = new GoogleDriveSharedBackupTransport({
      appId: "fixture-app",
      authorizationProvider: {
        authorize: async () => authorization,
        clear: vi.fn(),
      },
      drive,
    });

    await expect(transport.ensureStorage()).resolves.toEqual({
      appFolderId: "app-folder",
      exchangesFolderId: "exchanges-folder",
    });
    await expect(
      transport.grantExchangeAccess("recipient@example.com"),
    ).resolves.toEqual({
      appFolderId: "app-folder",
      drivePermissionId: "recipient-permission",
    });

    expect(fetch.mock.calls[3]?.[1]?.body).toContain(
      '"writersCanShare":false',
    );
    expect(fetch.mock.calls[4]?.[1]?.body).toContain('"role":"reader"');
    expect(fetch.mock.calls[5]?.[1]?.body).toContain('"role":"writer"');
  });

  it("uses the downloaded ETag for conditional dataset writes", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response('{"revisionId":"one"}', {
          headers: { ETag: '"drive-version-1"' },
        }),
      )
      .mockResolvedValueOnce(
        new Response('{"id":"dataset"}', {
          headers: { ETag: '"drive-version-2"' },
        }),
      );
    const drive = new GoogleDriveFileStore({ fetch });

    await expect(
      drive.readTextVersioned("dataset", authorization),
    ).resolves.toEqual({
      content: '{"revisionId":"one"}',
      etag: '"drive-version-1"',
    });
    await expect(
      drive.write("dataset", '{"revisionId":"two"}', authorization, {
        contentType: "application/json",
        ifMatch: '"drive-version-1"',
      }),
    ).resolves.toEqual({
      fileId: "dataset",
      etag: '"drive-version-2"',
    });
    const headers = fetch.mock.calls[1]?.[1]?.headers as Headers;
    expect(headers.get("If-Match")).toBe('"drive-version-1"');
  });

  it("reports a failed conditional write as a conflict", async () => {
    const drive = new GoogleDriveFileStore({
      fetch: vi.fn().mockResolvedValue(
        new Response("precondition failed", { status: 412 }),
      ),
    });
    await expect(
      drive.write("dataset", "stale", authorization, {
        ifMatch: '"old"',
      }),
    ).rejects.toMatchObject({ code: "conflict", status: 412 });
  });

  it("lists and updates explicit dataset permissions", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json({
          permissions: [
            {
              id: "participant",
              type: "user",
              role: "reader",
              emailAddress: "person@example.com",
              permissionDetails: [{ inherited: false }],
            },
          ],
        }),
      )
      .mockResolvedValueOnce(new Response(null, { status: 200 }));
    const drive = new GoogleDriveFileStore({ fetch });

    await expect(
      drive.listPermissions("dataset", authorization),
    ).resolves.toEqual([
      {
        permissionId: "participant",
        type: "user",
        role: "reader",
        emailAddress: "person@example.com",
      },
    ]);
    await drive.updatePermission(
      "dataset",
      "participant",
      "writer",
      authorization,
    );
    expect(fetch.mock.calls[1]?.[1]?.body).toBe('{"role":"writer"}');
  });

  it("defaults new snapshots into an app folder under the normal Drive root", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ files: [] }))
      .mockResolvedValueOnce(Response.json({ id: "app-folder" }))
      .mockResolvedValueOnce(Response.json({ files: [] }))
      .mockResolvedValueOnce(Response.json({ id: "snapshot" }));
    const drive = new GoogleDriveFileStore({
      fetch,
      randomUUID: () => "boundary",
    });
    const store = new GoogleDriveFileSnapshotStore({
      appId: "fixture-app",
      filename: "profile.json",
      parse: JSON.parse,
      drive,
    });

    await expect(store.find("fixture-app", authorization)).resolves.toBeNull();
    await expect(
      store.write(
        "fixture-app",
        { encrypted: true },
        authorization,
      ),
    ).resolves.toBe("snapshot");

    const appFolderBody = fetch.mock.calls[1]?.[1]?.body as string;
    expect(appFolderBody).toContain('"name":"Sync Kit - fixture-app"');
    expect(appFolderBody).not.toContain('"parents"');
    const snapshotBody = (fetch.mock.calls[3]?.[1]?.body as Blob);
    expect(await snapshotBody.text()).toContain('"parents":["app-folder"]');
  });

  it("returns Drive provenance for an explicitly opened key response", async () => {
    const fetch = vi.fn().mockResolvedValue(
      Response.json({
        id: "key-response",
        name: "response.json",
        owners: [
          {
            displayName: "Recipient",
            permissionId: "recipient-permission",
            emailAddress: "recipient@example.com",
          },
        ],
        sharingUser: {
          permissionId: "recipient-permission",
          emailAddress: "recipient@example.com",
        },
        lastModifyingUser: {
          permissionId: "recipient-permission",
          emailAddress: "recipient@example.com",
        },
      }),
    );
    const drive = new GoogleDriveFileStore({ fetch });

    const metadata = await drive.get("key-response", authorization);
    expect(metadata).toMatchObject({
      fileId: "key-response",
      owners: [{ permissionId: "recipient-permission" }],
      lastModifyingUser: { permissionId: "recipient-permission" },
    });
    expect(() =>
      assertDriveFileProvenance(metadata, {
        permissionId: "recipient-permission",
      }),
    ).not.toThrow();
  });

  it("rejects a key response modified by another folder writer", () => {
    expect(() =>
      assertDriveFileProvenance(
        {
          fileId: "response",
          name: "response.json",
          owners: [{ permissionId: "recipient" }],
          sharingUser: { permissionId: "recipient" },
          lastModifyingUser: { permissionId: "attacker" },
        },
        { permissionId: "recipient" },
      ),
    ).toThrow(/modified by another/u);
  });

  it("can isolate a recipient exchange inbox with limited folder access", async () => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(null, { status: 200 }),
    );
    const drive = new GoogleDriveFileStore({ fetch });

    await drive.setFolderLimitedAccess(
      "recipient-inbox",
      true,
      authorization,
    );

    expect(fetch.mock.calls[0]?.[0]).toContain(
      "/recipient-inbox?supportsAllDrives=true",
    );
    expect(fetch.mock.calls[0]?.[1]?.body).toBe(
      '{"inheritedPermissionsDisabled":true}',
    );
  });

  it("creates a user-visible file and shares only that file", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ id: "shared-file" }))
      .mockResolvedValueOnce(Response.json({ id: "permission" }));
    const drive = new GoogleDriveFileStore({
      fetch,
      randomUUID: () => "boundary",
    });

    await expect(
      drive.create(
        "fixture.sync-kit.json",
        '{"kind":"sync-kit-shared-backup"}',
        authorization,
        {
          contentType: "application/json",
          appProperties: {
            "sync-kit-app-id": "fixture-app",
            "sync-kit-kind": "shared-backup",
          },
        },
      ),
    ).resolves.toBe("shared-file");
    await expect(
      drive.share(
        "shared-file",
        "recipient@example.com",
        "reader",
        authorization,
      ),
    ).resolves.toBe("permission");

    const createBody = fetch.mock.calls[0]?.[1]?.body as Blob;
    const multipart = await createBody.text();
    expect(multipart).toContain('"writersCanShare":false');
    expect(multipart).not.toContain("appDataFolder");
    expect(fetch.mock.calls[1]?.[0]).toContain(
      "/shared-file/permissions?",
    );
    expect(fetch.mock.calls[1]?.[1]?.body).toBe(
      '{"type":"user","role":"reader","emailAddress":"recipient@example.com"}',
    );
  });

  it("lists only accessible files inside a selected namespace", async () => {
    const fetch = vi.fn().mockResolvedValue(
      Response.json({
        files: [
          {
            id: "backup",
            name: "profile.sync-kit.json",
            appProperties: {
              "sync-kit-app-id": "fixture-app",
              "sync-kit-kind": "shared-backup",
            },
            capabilities: { canEdit: false, canShare: false },
          },
        ],
      }),
    );
    const drive = new GoogleDriveFileStore({ fetch });

    await expect(
      drive.list(authorization, {
        parentId: "selected-folder",
        appProperties: {
          "sync-kit-app-id": "fixture-app",
          "sync-kit-kind": "shared-backup",
        },
      }),
    ).resolves.toEqual({
      files: [
        {
          fileId: "backup",
          name: "profile.sync-kit.json",
          appProperties: {
            "sync-kit-app-id": "fixture-app",
            "sync-kit-kind": "shared-backup",
          },
          capabilities: { canEdit: false, canShare: false },
        },
      ],
    });
    const query = new URL(fetch.mock.calls[0]?.[0] as string).searchParams.get(
      "q",
    );
    expect(query).toContain("'selected-folder' in parents");
    expect(query).toContain(
      "appProperties has { key='sync-kit-app-id' and value='fixture-app' }",
    );
  });
});
