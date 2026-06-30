import { describe, expect, it, vi } from "vitest";
import {
  GoogleDriveAppDataStore,
  GoogleDriveSnapshotStore,
} from "../src/stores/google-drive/index.js";

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
