import { describe, expect, it, vi } from "vitest";
import {
  assertDriveFileProvenance,
  GoogleDriveAppDataStore,
  GoogleDriveFileStore,
  GoogleDriveFileSnapshotStore,
  GoogleDriveSnapshotStore,
  listAccessibleSyncKitAppFolders,
} from "../src/stores/google-drive/index.js";
import { GoogleDriveSharedBackupTransport } from "../src/stores/google-drive/sharing.js";

const authorization = { accessToken: "token" };

function requestHeader(
  init: RequestInit | undefined,
  name: string,
): string | null {
  const headers = init?.headers;
  if (!headers) return null;
  if (headers instanceof Headers) return headers.get(name);
  if (Array.isArray(headers)) {
    const match = headers.find(([key]) => key.toLowerCase() === name.toLowerCase());
    return match?.[1] ?? null;
  }
  return headers[name] ?? headers[name.toLowerCase()] ?? null;
}

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

  it("retries managed storage initialization after a transient failure", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(new Response("temporary", { status: 500 }))
      .mockResolvedValueOnce(Response.json({ files: [] }))
      .mockResolvedValueOnce(Response.json({ id: "app-folder" }))
      .mockResolvedValueOnce(Response.json({ files: [] }))
      .mockResolvedValueOnce(Response.json({ id: "exchanges-folder" }));
    const transport = new GoogleDriveSharedBackupTransport({
      appId: "fixture-app",
      authorizationProvider: {
        authorize: async () => authorization,
        clear: vi.fn(),
      },
      drive: new GoogleDriveFileStore({
        fetch,
        randomUUID: () => "boundary",
      }),
    });

    await expect(transport.ensureStorage()).rejects.toMatchObject({
      code: "provider",
      status: 500,
    });
    await expect(transport.ensureStorage()).resolves.toEqual({
      appFolderId: "app-folder",
      exchangesFolderId: "exchanges-folder",
    });
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

  it("reads v2 write metadata from the JSON body", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(
      Response.json({ etag: '"rev-etag"', headRevisionId: "rev-7" }),
    );
    const drive = new GoogleDriveFileStore({ fetch });

    await expect(
      drive.getV2WriteHead("dataset", authorization),
    ).resolves.toEqual({
      etag: '"rev-etag"',
      headRevisionId: "rev-7",
    });
    expect(String(fetch.mock.calls[0]?.[0])).toContain("/drive/v2/files/");
  });

  it("uploads via the v2 media endpoint with If-Match", async () => {
    const fetch = vi.fn().mockResolvedValueOnce(
      Response.json({
        id: "dataset",
        etag: '"rev-8-etag"',
        headRevisionId: "rev-8",
      }),
    );
    const drive = new GoogleDriveFileStore({ fetch });

    await expect(
      drive.writeV2Media("dataset", '{"next":true}', authorization, {
        contentType: "application/json",
        ifMatch: '"rev-7-etag"',
      }),
    ).resolves.toEqual({
      fileId: "dataset",
      etag: '"rev-8-etag"',
      headRevisionId: "rev-8",
    });
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(String(url)).toContain("/upload/drive/v2/files/");
    expect((init as RequestInit).method).toBe("PUT");
    expect(requestHeader(init as RequestInit, "If-Match")).toBe('"rev-7-etag"');
  });

  it("reports a failed v2 conditional write as a conflict", async () => {
    const drive = new GoogleDriveFileStore({
      fetch: vi.fn().mockResolvedValue(
        new Response("precondition failed", { status: 412 }),
      ),
    });
    await expect(
      drive.writeV2Media("dataset", "stale", authorization, {
        ifMatch: '"old"',
      }),
    ).rejects.toMatchObject({ code: "conflict", status: 412 });
  });

  it("maps missing v2 endpoints to DriveV2UnavailableError", async () => {
    const drive = new GoogleDriveFileStore({
      fetch: vi.fn().mockResolvedValue(new Response("gone", { status: 404 })),
    });
    await expect(
      drive.getV2WriteHead("dataset", authorization),
    ).rejects.toMatchObject({ name: "SyncKitError", code: "not-found" });
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

  it("retries snapshot folder initialization after a transient failure", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(new Response("temporary", { status: 500 }))
      .mockResolvedValueOnce(Response.json({ files: [] }))
      .mockResolvedValueOnce(Response.json({ id: "app-folder" }))
      .mockResolvedValueOnce(Response.json({ files: [] }));
    const store = new GoogleDriveFileSnapshotStore({
      appId: "fixture-app",
      filename: "profile.json",
      parse: JSON.parse,
      drive: new GoogleDriveFileStore({
        fetch,
        randomUUID: () => "boundary",
      }),
    });

    await expect(
      store.find("fixture-app", authorization),
    ).rejects.toMatchObject({ code: "provider", status: 500 });
    await expect(
      store.find("fixture-app", authorization),
    ).resolves.toBeNull();
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

  it("moves a file to trash with a metadata PATCH", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    const drive = new GoogleDriveFileStore({ fetch });

    await drive.trash("retired-dataset", authorization);

    expect(fetch.mock.calls[0]?.[0]).toContain(
      "/retired-dataset?supportsAllDrives=true",
    );
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({
      method: "PATCH",
      body: '{"trashed":true}',
    });
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

  it("lists accessible sync-kit app-root folders for one application", async () => {
    const fetch = vi.fn().mockResolvedValue(
      Response.json({
        files: [
          {
            id: "folder-a",
            name: "EasyBC — Personal",
            mimeType: "application/vnd.google-apps.folder",
            appProperties: {
              "sync-kit-app-id": "easy-bc",
              "sync-kit-kind": "app-root",
            },
          },
          {
            id: "file-a",
            name: "not-a-folder.json",
            mimeType: "application/json",
            appProperties: {
              "sync-kit-app-id": "easy-bc",
              "sync-kit-kind": "dataset",
            },
          },
        ],
      }),
    );

    await expect(
      listAccessibleSyncKitAppFolders({
        appId: "easy-bc",
        authorization,
        drive: new GoogleDriveFileStore({ fetch }),
      }),
    ).resolves.toEqual([
      {
        appFolderId: "folder-a",
        name: "EasyBC — Personal",
      },
    ]);
  });
});

describe("Google Drive dataset change tokens", () => {
  const datasetProperties = {
    "sync-kit-app-id": "fixture-app",
    "sync-kit-protocol": "sharing-v1",
    "sync-kit-kind": "dataset",
    "sync-kit-dataset-id": "ds-1",
  };

  const makeEnvelope = async () => {
    const { createWebCryptoSharingIdentity, createSharedBackupEnvelopeV1 } =
      await import("../src/sharing/web-crypto.js");
    const owner = await createWebCryptoSharingIdentity();
    return createSharedBackupEnvelopeV1(
      { marker: "token-test" },
      {
        serialize: (value) => value,
        parse: (value) => value as { marker: string },
      },
      owner,
      {
        appId: "fixture-app",
        backupId: "ds-1",
        revisionId: "revision-1",
        createdAt: "2026-07-01T12:00:00.000Z",
        participants: [{ publicKey: owner.publicKey, role: "owner" as const }],
      },
    );
  };

  it("falls back to headRevisionId when Drive sends no ETag header", async () => {
    const envelope = await makeEnvelope();
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json({
          id: "ds-file",
          name: "ds-1.sync-kit.json",
          headRevisionId: "rev-7",
          version: "3",
          appProperties: datasetProperties,
        }),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(envelope)));
    const transport = new GoogleDriveSharedBackupTransport({
      appId: "fixture-app",
      authorizationProvider: { authorize: async () => authorization, clear: vi.fn() },
      drive: new GoogleDriveFileStore({ fetch }),
    });

    const dataset = await transport.readDataset("ds-file");
    expect(dataset.version).toBe("rev-7");
    expect(dataset.datasetId).toBe("ds-1");
  });

  it("deletes the orphan file when the post-create read-back fails", async () => {
    const fetch = vi
      .fn()
      // ensureStorage: selectedAppFolderId set, so only the exchanges lookup
      .mockResolvedValueOnce(
        Response.json({ files: [{ id: "exchanges", name: "exchanges" }] }),
      )
      // createDataset upload
      .mockResolvedValueOnce(Response.json({ id: "orphan-file" }))
      // read-back metadata: managed, but content will be junk
      .mockResolvedValueOnce(
        Response.json({
          id: "orphan-file",
          name: "ds-1.sync-kit.json",
          headRevisionId: "rev-1",
          appProperties: datasetProperties,
        }),
      )
      .mockResolvedValueOnce(new Response("not-an-envelope"))
      // rollback delete
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const transport = new GoogleDriveSharedBackupTransport({
      appId: "fixture-app",
      authorizationProvider: { authorize: async () => authorization, clear: vi.fn() },
      drive: new GoogleDriveFileStore({ fetch }),
      selectedAppFolderId: "app-folder",
    });
    const envelope = await makeEnvelope();

    await expect(transport.createDataset("ds-1", envelope)).rejects.toThrow();
    const deleteCall = fetch.mock.calls.find(
      (call) => (call[1] as RequestInit | undefined)?.method === "DELETE",
    );
    expect(String(deleteCall?.[0])).toContain("orphan-file");
  });

  it("uses v2 conditional writes with headRevisionId version tokens", async () => {
    const envelope = await makeEnvelope();
    const next = { ...envelope, revisionId: "revision-2", parentRevisionId: "revision-1" };
    const current = {
      datasetId: "ds-1",
      fileId: "ds-file",
      name: "ds-1.sync-kit.json",
      envelope,
      version: "rev-7",
    };
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json({ etag: '"rev-7-etag"', headRevisionId: "rev-7" }),
      )
      .mockResolvedValueOnce(
        Response.json({
          id: "ds-file",
          etag: '"rev-8-etag"',
          headRevisionId: "rev-8",
        }),
      );
    const transport = new GoogleDriveSharedBackupTransport({
      appId: "fixture-app",
      authorizationProvider: { authorize: async () => authorization, clear: vi.fn() },
      drive: new GoogleDriveFileStore({ fetch }),
    });

    const written = await transport.writeDataset(current, next);
    expect(written.version).toBe("rev-8");
    const preflightUrl = String(fetch.mock.calls[0]?.[0]);
    const uploadInit = fetch.mock.calls[1]?.[1] as RequestInit;
    expect(preflightUrl).toContain("/drive/v2/files/");
    expect(uploadInit.method).toBe("PUT");
    expect(requestHeader(uploadInit, "If-Match")).toBe('"rev-7-etag"');
  });

  it("reports stale v2 If-Match writes as conflicts", async () => {
    const envelope = await makeEnvelope();
    const next = { ...envelope, revisionId: "revision-2", parentRevisionId: "revision-1" };
    const current = {
      datasetId: "ds-1",
      fileId: "ds-file",
      name: "ds-1.sync-kit.json",
      envelope,
      version: "rev-7",
    };
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json({ etag: '"rev-7-etag"', headRevisionId: "rev-7" }),
      )
      .mockResolvedValueOnce(
        new Response("precondition failed", { status: 412 }),
      );
    const transport = new GoogleDriveSharedBackupTransport({
      appId: "fixture-app",
      authorizationProvider: { authorize: async () => authorization, clear: vi.fn() },
      drive: new GoogleDriveFileStore({ fetch }),
    });

    await expect(transport.writeDataset(current, next)).rejects.toMatchObject({
      code: "conflict",
      status: 412,
    });
  });

  it("falls back to v3 preflight-only writes when v2 is unavailable", async () => {
    const envelope = await makeEnvelope();
    const next = { ...envelope, revisionId: "revision-2", parentRevisionId: "revision-1" };
    const current = {
      datasetId: "ds-1",
      fileId: "ds-file",
      name: "ds-1.sync-kit.json",
      envelope,
      version: "rev-7",
    };
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(new Response("gone", { status: 404 }))
      .mockResolvedValueOnce(
        Response.json({
          id: "ds-file",
          name: "ds-1.sync-kit.json",
          headRevisionId: "rev-7",
          appProperties: datasetProperties,
        }),
      )
      .mockResolvedValueOnce(Response.json({ id: "ds-file" }))
      .mockResolvedValueOnce(
        Response.json({
          id: "ds-file",
          name: "ds-1.sync-kit.json",
          headRevisionId: "rev-8",
          appProperties: datasetProperties,
        }),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify(next)));
    const transport = new GoogleDriveSharedBackupTransport({
      appId: "fixture-app",
      authorizationProvider: { authorize: async () => authorization, clear: vi.fn() },
      drive: new GoogleDriveFileStore({ fetch }),
    });

    const written = await transport.writeDataset(current, next);
    expect(written.version).toBe("rev-8");
    const urls = fetch.mock.calls.map((call) => String(call[0]));
    expect(urls[0]).toContain("/drive/v2/files/");
    expect(urls[1]).toContain("/drive/v3/files/");
    const uploadInit = fetch.mock.calls[2]?.[1] as RequestInit;
    expect(requestHeader(uploadInit, "If-Match")).toBeNull();
  });
});
