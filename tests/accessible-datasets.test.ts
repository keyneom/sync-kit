import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { GoogleDriveFileStore } from "../src/stores/google-drive/index.js";
import {
  GoogleDriveSharedBackupTransport,
  listAccessibleSyncKitDatasets,
  type AccessibleSyncKitDataset,
} from "../src/stores/google-drive/sharing.js";

type DiscoveryFixture = {
  appId: string;
  pages: { files: unknown[]; nextPageToken?: string }[];
  expected: AccessibleSyncKitDataset[];
};

const fixture = JSON.parse(
  readFileSync(
    new URL(
      "../fixtures/sharing-v1/accessible-datasets.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as DiscoveryFixture;

const authorization = { accessToken: "token" };

function requestUrl(input: RequestInfo | URL): URL {
  if (typeof input === "string") return new URL(input);
  if (input instanceof URL) return input;
  return new URL(input.url);
}

describe("accessible sync-kit dataset discovery", () => {
  it("exhausts pages, filters malformed metadata, deduplicates, and sorts like Kotlin", async () => {
    const fetch = vi.fn(async (...args: [RequestInfo | URL, RequestInit?]) => {
      const url = requestUrl(args[0]);
      const page = url.searchParams.get("pageToken") ? fixture.pages[1] : fixture.pages[0];
      return Response.json(page);
    });
    const drive = new GoogleDriveFileStore({ fetch });

    await expect(
      listAccessibleSyncKitDatasets({
        appId: fixture.appId,
        authorization,
        drive,
      }),
    ).resolves.toEqual(fixture.expected);

    expect(fetch).toHaveBeenCalledTimes(2);
    const [firstCall, secondCall] = fetch.mock.calls;
    if (!firstCall || !secondCall) throw new Error("Expected two Drive pages.");
    const firstUrl = requestUrl(firstCall[0]);
    const secondUrl = requestUrl(secondCall[0]);
    expect(firstUrl.searchParams.get("q")).toContain(
      "key='sync-kit-app-id' and value='fixture-app'",
    );
    expect(firstUrl.searchParams.get("q")).toContain(
      "key='sync-kit-protocol' and value='sharing-v1'",
    );
    expect(firstUrl.searchParams.get("q")).toContain(
      "key='sync-kit-kind' and value='dataset'",
    );
    expect(secondUrl.searchParams.get("pageToken")).toBe("page-2");
    expect(fetch.mock.calls.every((call) => call[1]?.method === undefined)).toBe(true);
  });

  it("rejects blank app IDs before touching Drive", async () => {
    const fetch = vi.fn();
    await expect(
      listAccessibleSyncKitDatasets({
        appId: " ",
        authorization,
        drive: new GoogleDriveFileStore({ fetch }),
      }),
    ).rejects.toThrow("appId must not be empty");
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("read-only shared dataset listing", () => {
  it("lists a selected app folder without creating an exchanges folder", async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json({ files: [] }));
    const transport = new GoogleDriveSharedBackupTransport({
      appId: "fixture-app",
      authorizationProvider: {
        authorize: async () => authorization,
        clear: () => undefined,
      },
      selectedAppFolderId: "selected-folder",
      drive: new GoogleDriveFileStore({ fetch }),
    });

    await expect(transport.listDatasets()).resolves.toEqual([]);

    expect(fetch).toHaveBeenCalledOnce();
    const url = new URL(String(fetch.mock.calls[0]?.[0]));
    expect(url.searchParams.get("q")).toContain("'selected-folder' in parents");
    expect(fetch.mock.calls[0]?.[1]?.method).toBeUndefined();
  });

  it("returns empty without creating storage when no app-root exists", async () => {
    const fetch = vi.fn().mockResolvedValue(Response.json({ files: [] }));
    const transport = new GoogleDriveSharedBackupTransport({
      appId: "fixture-app",
      authorizationProvider: {
        authorize: async () => authorization,
        clear: () => undefined,
      },
      drive: new GoogleDriveFileStore({ fetch }),
    });

    await expect(transport.listDatasets()).resolves.toEqual([]);

    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch.mock.calls[0]?.[1]?.method).toBeUndefined();
  });
});
